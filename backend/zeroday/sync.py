"""Background sync: Zero-Day Radar -> local Postgres.

Runs in a daemon thread started from the FastAPI lifespan (see main.py).
Every cycle (ZERODAY_SYNC_SECONDS, default 300):

  1. GET /feed?since=<server_time>  -> upsert into zeroday_cves
  2. GET /sources, /metrics, /signals -> zd_cache
  3. refresh missing package->CVE mappings (Ubuntu via OSV)

Once every ZERODAY_FULL_SYNC_DAYS (default 7) the feed is pulled without
`since`, and CVEs that are no longer returned are deleted (the Zero-Day
API never reports retention deletions; see its docs section 7).

Can also be run by hand from the backend directory:
    python -m zeroday.sync --once [--full]
"""

import os
import threading
import time
from datetime import datetime, timezone

from core.config import api_logger
from zeroday import client, store

SYNC_SECONDS = int(os.environ.get("ZERODAY_SYNC_SECONDS", "300"))
FULL_SYNC_DAYS = int(os.environ.get("ZERODAY_FULL_SYNC_DAYS", "7"))
PAGE_LIMIT = 1000

_thread: threading.Thread | None = None


def _pull_feed(since: str | None) -> tuple[set[str], str | None, int]:
    """Page through /feed; returns (ids_seen, next_server_time, upserted)."""
    ids: set[str] = set()
    next_since: str | None = None
    offset = 0
    upserted = 0

    while True:
        page = client.feed(since=since, limit=PAGE_LIMIT, offset=offset)

        if page.get("generated_at") is None:
            # Zero-Day has no data (e.g. its database is down). Not the
            # same as "no vulnerabilities" — leave our copy untouched.
            api_logger.warning("zeroday_sync_empty_radar generated_at=null")
            return ids, None, upserted

        if next_since is None:
            next_since = page.get("server_time")

        items = page.get("items") or []
        upserted += store.upsert_cves(items)
        ids.update(item["id"] for item in items if item.get("id"))

        offset += len(items)
        if offset >= int(page.get("total") or 0) or not items:
            return ids, next_since, upserted


def sync_once(full: bool = False) -> dict:
    """One sync cycle. Returns a small stats dict; stores errors in state."""
    started = time.monotonic()
    state = store.get_sync_state()

    if not full and state["last_full_sync_at"] is None:
        full = True  # first ever run is a full sync
    elif not full and state["last_full_sync_at"] is not None:
        age = datetime.now(timezone.utc) - state["last_full_sync_at"]
        full = age.days >= FULL_SYNC_DAYS

    try:
        since = None if full else state["server_time"]
        ids, next_since, upserted = _pull_feed(since)

        deleted = 0
        if full and ids:
            deleted = store.delete_cves_not_in(ids)

        # Cache the companion endpoints for the status pill / signals panel.
        for key, fetch in (
            ("sources", client.sources),
            ("metrics", client.metrics),
            ("signals", client.signals),
        ):
            try:
                store.cache_put(key, fetch())
            except client.ZeroDayUnavailable as exc:
                api_logger.warning("zeroday_cache_refresh_failed key=%s error=%s", key, exc)

        store.set_sync_state(server_time=next_since, full=full and bool(ids))

        stats = {
            "full": full,
            "upserted": upserted,
            "deleted": deleted,
            "duration_s": round(time.monotonic() - started, 1),
        }
        api_logger.info(
            "zeroday_sync_completed full=%s upserted=%s deleted=%s duration_s=%s",
            full, upserted, deleted, stats["duration_s"],
        )

    except client.ZeroDayUnavailable as exc:
        store.set_sync_state(error=str(exc)[:2000])
        api_logger.error("zeroday_sync_failed error=%s", exc)
        return {"error": str(exc)}

    # Package->CVE mapping for pending packages that have none yet
    # (Ubuntu/OSV; RHEL mappings arrive with patch discovery instead).
    try:
        from cve_mapping import mapper

        mapped = mapper.refresh_missing()
        if mapped:
            api_logger.info("cve_mapping_refreshed packages=%s", mapped)
    except Exception:  # mapping must never break the sync loop
        api_logger.exception("cve_mapping_refresh_failed")

    return stats


def _loop() -> None:
    while True:
        try:
            sync_once()
        except Exception:
            api_logger.exception("zeroday_sync_unexpected_error")
        time.sleep(SYNC_SECONDS)


def start_background() -> None:
    """Start the sync thread once; safe to call repeatedly."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_loop, name="zeroday-sync", daemon=True)
    _thread.start()
    api_logger.info("zeroday_sync_started interval_s=%s base=%s", SYNC_SECONDS, client.BASE_URL)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Zero-Day Radar sync")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--full", action="store_true", help="force a full sync")
    args = parser.parse_args()

    if args.once:
        print(sync_once(full=args.full))
    else:
        _loop()
