"""A1/A3/A9/A10 — the Zero-Day endpoints the UI calls.

GET /api/zeroday/status      -> sync pill (freshness, feed health, credits)
GET /api/zeroday/fleet-cves  -> Attention Required + Vulnerabilities list
GET /api/zeroday/cve/{id}    -> detail panel (local exposure + full intel)
GET /api/zeroday/signals     -> early-warning chatter, fleet matches first

The browser never talks to Zero-Day Radar; these endpoints serve the
synced copy and, for the detail panel only, a cached pass-through of
GET /item/{cve}.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from database import get_connection
from core.config import api_logger
from services import fleet_join
from zeroday import client, store

router = APIRouter()

ITEM_CACHE_SECONDS = 900          # 15 min
STALE_SYNC_SECONDS = 900          # pill turns "degraded" after this


# ---------------------------------------------------------------- A1


@router.get("/api/zeroday/status")
def zeroday_status():
    state = store.get_sync_state()
    sources, _ = store.cache_get("sources")
    metrics, _ = store.cache_get("metrics")

    feeds_total = feeds_healthy = 0
    for feed in sources or []:
        if not feed.get("enabled"):
            continue
        feeds_total += 1
        failing = (
            feed.get("last_error_at")
            and (feed.get("last_success") is None
                 or feed["last_error_at"] > feed["last_success"])
        )
        if not failing:
            feeds_healthy += 1

    generated_at = (metrics or {}).get("generated_at")

    synced_at = state["last_sync_at"]
    stale = (
        synced_at is None
        or (datetime.now(timezone.utc) - synced_at).total_seconds()
        > STALE_SYNC_SECONDS
    )

    return {
        "synced_at": synced_at,
        "generated_at": generated_at,
        "feeds_healthy": feeds_healthy,
        "feeds_total": feeds_total,
        # generated_at null means the radar itself has no data — show
        # "intel unavailable", never zero vulnerabilities.
        "degraded": stale or generated_at is None,
        "last_error": state["last_error"],
        # Licence requirement: display these wherever radar data is shown.
        "attributions": (metrics or {}).get("attributions") or [],
    }


# ---------------------------------------------------------------- A3


@router.get("/api/zeroday/fleet-cves")
def fleet_cves(
    tab: str = Query("all", pattern="^(exploited|kev|all)$"),
    severity: str | None = Query(None, description="comma list"),
    exploitation: str | None = Query(
        None, pattern="^(exploited|reported|poc|none|unknown)$"
    ),
    source: str | None = Query(None, pattern="^(zeroday|distro)$"),
    q: str | None = Query(None, description="match CVE id or title"),
):
    cves = fleet_join.fleet_cves()

    kpis = {
        "total": len(cves),
        "exploited": sum(1 for c in cves if c["exploitation"] == "exploited"),
        "kev_due_7d": sum(
            1 for c in cves
            if c["days_left"] is not None and 0 <= c["days_left"] <= 7
        ),
        "kev_overdue": sum(
            1 for c in cves
            if c["days_left"] is not None and c["days_left"] < 0
        ),
        "servers_exposed": len(
            {
                s["asset_id"]
                for c in cves if c["exploitation"] == "exploited"
                for s in c["servers"]
            }
        ),
    }

    if tab == "exploited":
        cves = [c for c in cves if c["exploitation"] == "exploited"]
    elif tab == "kev":
        cves = [
            c for c in cves
            if c["days_left"] is not None and c["days_left"] <= 7
        ]

    if severity:
        wanted = {s.strip().lower() for s in severity.split(",") if s.strip()}
        cves = [c for c in cves if c["severity"] in wanted]
    if exploitation:
        cves = [c for c in cves if c["exploitation"] == exploitation]
    if source:
        cves = [c for c in cves if c["source"] == source]
    if q:
        needle = q.lower()
        cves = [
            c for c in cves
            if needle in c["cve"].lower() or needle in (c["title"] or "").lower()
        ]

    return {"kpis": kpis, "total": len(cves), "items": cves}


# ---------------------------------------------------------------- A9


def _intel_for(cve_id: str) -> dict | None:
    """Full Zero-Day record: 15-min cache, else live, else synced copy."""
    cache_key = f"item:{cve_id}"
    cached, _ = store.cache_get(cache_key, max_age_seconds=ITEM_CACHE_SECONDS)
    if cached is not None:
        return cached or None  # {} caches a confirmed "not tracked"

    try:
        record = client.item(cve_id)
        store.cache_put(cache_key, record if record is not None else {})
        return record
    except client.ZeroDayUnavailable as exc:
        api_logger.warning("zeroday_item_unavailable cve=%s error=%s", cve_id, exc)

    # Radar unreachable: fall back to the record from the last feed sync.
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT record FROM zeroday_cves WHERE cve_id = %s", (cve_id,)
            )
            row = cursor.fetchone()
            return row[0] if row else None
    finally:
        connection.close()


@router.get("/api/zeroday/cve/{cve_id}")
def cve_detail(cve_id: str):
    cve_id = cve_id.upper()

    exposure = next(
        (c for c in fleet_join.fleet_cves() if c["cve"] == cve_id), None
    )
    intel = _intel_for(cve_id)

    if exposure is None and intel is None:
        raise HTTPException(
            status_code=404,
            detail=f"{cve_id} is not tracked and no fleet package maps to it",
        )

    if intel:
        intel = dict(intel)
        intel.pop("context_evidence", None)  # heavy and not shown in the UI

    return {
        "cve": cve_id,
        "source": "zeroday" if intel else "distro",
        "exposure": exposure,   # null when no pending update maps to it
        "intel": intel,         # null for distro-only CVEs
    }


# ---------------------------------------------------------------- A10


def _fleet_tokens() -> set[str]:
    """Lowercased package names + hostnames to match signals against."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT package FROM pending_packages
                UNION
                SELECT DISTINCT hostname FROM assets WHERE status = 'ACTIVE'
                """
            )
            return {row[0].lower() for row in cursor.fetchall() if row[0]}
    finally:
        connection.close()


@router.get("/api/zeroday/signals")
def zeroday_signals():
    clusters, fetched_at = store.cache_get("signals")
    if clusters is None:
        return {"fetched_at": None, "items": []}

    tokens = _fleet_tokens()

    def matches(cluster: dict) -> bool:
        candidates = [cluster.get("vendor") or ""]
        insights = cluster.get("insights") or {}
        candidates += insights.get("products_mentioned") or []
        for candidate in candidates:
            needle = candidate.lower().strip()
            if len(needle) < 3 or needle == "unattributed":
                continue
            for token in tokens:
                if needle in token or token in needle:
                    return True
        return False

    items = [dict(c, fleet_match=matches(c)) for c in clusters]
    items.sort(key=lambda c: (not c["fleet_match"]))
    return {"fetched_at": fetched_at, "items": items}
