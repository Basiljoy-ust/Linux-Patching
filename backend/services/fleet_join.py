"""The CVE <-> server <-> package join.

Everything Zero-Day-related the UI shows is a shape of one join:

    pending_packages  (what each server can upgrade right now)
      x package_cves  (which CVEs those upgrades address, per distro)
      x zeroday_cves  (what Zero-Day Radar knows about those CVEs)

CVEs found by the distro mapping but not tracked by Zero-Day are still
returned, with source="distro" and the advisory severity — they are real,
just without exploitation intelligence.
"""

import json
from datetime import date

from database import get_connection
from zeroday import risk


# ---------------------------------------------------------------- pending


def save_pending_packages(asset_id: str, discovery: dict) -> int:
    """Replace the stored pending packages for an asset from a discovery."""
    packages = discovery.get("packages") or []

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM pending_packages WHERE asset_id = %s",
                    (asset_id,),
                )
                cursor.executemany(
                    """
                    INSERT INTO pending_packages (
                        asset_id, package, current_version,
                        available_version, checked_at
                    )
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (asset_id, package) DO UPDATE SET
                        current_version = EXCLUDED.current_version,
                        available_version = EXCLUDED.available_version,
                        checked_at = NOW()
                    """,
                    [
                        (
                            asset_id,
                            package["name"],
                            package.get("current_version"),
                            package.get("available_version"),
                        )
                        for package in packages
                        if package.get("name")
                    ],
                )
    finally:
        connection.close()

    return len(packages)


def remove_pending_packages(asset_id: str, packages: list[str]) -> None:
    """Drop packages from pending after they were patched successfully."""
    if not packages:
        return
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM pending_packages
                    WHERE asset_id = %s AND package = ANY(%s)
                    """,
                    (asset_id, packages),
                )
    finally:
        connection.close()


# ---------------------------------------------------------------- the join


_JOIN_SQL = """
    SELECT
        pp.asset_id::text,
        a.hostname,
        a.os,
        a.os_family,
        pp.package,
        pp.current_version,
        pp.available_version,
        pc.cve_id,
        pc.distro_severity,
        pc.title AS distro_title,
        pc.fixed_version,
        z.cve_id IS NOT NULL AS tracked,
        z.title,
        z.severity,
        z.maturity,
        z.exploited,
        z.ransomware,
        z.true_zero_day,
        z.public_poc,
        z.kev,
        z.kev_due_date,
        z.urgency,
        z.priority_score,
        z.cvss_score,
        z.epss_score,
        z.confidence,
        z.vendor
    FROM pending_packages pp
    JOIN assets a       ON a.id = pp.asset_id
    JOIN package_cves pc ON pc.package = pp.package
                        AND pc.os_family = a.os_family
    LEFT JOIN zeroday_cves z ON z.cve_id = pc.cve_id
    WHERE a.status = 'ACTIVE'
"""

_COLUMNS = [
    "asset_id", "hostname", "os", "os_family", "package",
    "current_version", "available_version", "cve_id", "distro_severity",
    "distro_title", "fixed_version", "tracked", "title", "severity", "maturity",
    "exploited", "ransomware", "true_zero_day", "public_poc", "kev",
    "kev_due_date", "urgency", "priority_score", "cvss_score",
    "epss_score", "confidence", "vendor",
]


def _join_rows(asset_id: str | None = None) -> list[dict]:
    sql = _JOIN_SQL
    params: tuple = ()
    if asset_id is not None:
        sql += " AND pp.asset_id = %s"
        params = (asset_id,)

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows = [dict(zip(_COLUMNS, row)) for row in cursor.fetchall()]
    finally:
        connection.close()

    for row in rows:
        if not row["tracked"]:
            row["source"] = "distro"
            row["severity"] = row["distro_severity"] or "unknown"
            row["title"] = row["distro_title"] or row["cve_id"]
        else:
            row["source"] = "zeroday"
    return rows


def _cve_shape(cve_id: str, rows: list[dict]) -> dict:
    """Collapse the join rows of one CVE into the API shape."""
    first = rows[0]
    if first["source"] == "distro":
        # distro severity can differ per package row; keep the worst
        first = max(
            rows, key=lambda r: risk.SEVERITY_RANK.get(r["severity"] or "unknown", 0)
        )
    exploitation = risk.exploitation_of(first)
    due = first["kev_due_date"]

    servers: dict[str, dict] = {}
    for row in rows:
        server = servers.setdefault(
            row["asset_id"],
            {
                "asset_id": row["asset_id"],
                "hostname": row["hostname"],
                "os": row["os"],
                "packages": [],
            },
        )
        server["packages"].append(
            {
                "package": row["package"],
                "installed": row["current_version"],
                "fixed_by": row["available_version"],
            }
        )

    return {
        "cve": cve_id,
        "title": first["title"],
        "vendor": first["vendor"],
        "severity": first["severity"],
        "exploitation": exploitation,
        "badges": risk.badges(first),
        "source": first["source"],
        "confidence": first["confidence"],
        "cvss": float(first["cvss_score"]) if first["cvss_score"] is not None else None,
        "epss": float(first["epss_score"]) if first["epss_score"] is not None else None,
        "priority": float(first["priority_score"])
        if first["priority_score"] is not None else None,
        "kev": bool(first["kev"]),
        "due_date": due.isoformat() if isinstance(due, date) else due,
        "days_left": risk.days_left(due),
        "urgency": first["urgency"],
        "urgency_label": risk.urgency_label(first["urgency"]),
        "servers": sorted(servers.values(), key=lambda s: s["hostname"]),
        "packages": sorted({row["package"] for row in rows}),
        "score": risk.score(first),
    }


def fleet_cves(asset_id: str | None = None) -> list[dict]:
    """All CVEs addressable by pending updates, riskiest first."""
    by_cve: dict[str, list[dict]] = {}
    for row in _join_rows(asset_id):
        by_cve.setdefault(row["cve_id"], []).append(row)

    shaped = [_cve_shape(cve_id, rows) for cve_id, rows in by_cve.items()]
    shaped.sort(key=lambda c: c["score"], reverse=True)
    return shaped


# ---------------------------------------------------------------- shapes


def asset_vulnerabilities(asset_id: str) -> dict:
    """Per-server slice: exposure counts + the CVEs its updates fix."""
    cves = fleet_cves(asset_id=asset_id)

    checked_at = None
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT MAX(checked_at) FROM pending_packages WHERE asset_id = %s",
                (asset_id,),
            )
            row = cursor.fetchone()
            checked_at = row[0] if row else None
    finally:
        connection.close()

    exploited = [c for c in cves if c["exploitation"] == "exploited"]
    due_soon = [
        c for c in cves
        if c["days_left"] is not None and c["days_left"] <= 7
    ]

    items = [
        {
            **{k: c[k] for k in (
                "cve", "title", "severity", "exploitation", "badges",
                "source", "due_date", "days_left", "urgency", "urgency_label",
            )},
            "fixed_by": [
                pkg for server in c["servers"]
                if server["asset_id"] == asset_id
                for pkg in server["packages"]
            ],
        }
        for c in cves
    ]

    return {
        "asset_id": asset_id,
        "checked_at": checked_at,
        "exposure": {
            "total": len(cves),
            "exploited": len(exploited),
            "kev_due_7d": len(due_soon),
        },
        "items": items,
    }


def pending_by_server() -> list[dict]:
    """The Updates view: every server's pending packages, with their CVEs."""
    cve_rows = _join_rows()
    cves_by_asset_pkg: dict[tuple, list[dict]] = {}
    for row in cve_rows:
        key = (row["asset_id"], row["package"])
        cves_by_asset_pkg.setdefault(key, []).append(
            {
                "id": row["cve_id"],
                "severity": row["severity"],
                "exploitation": risk.exploitation_of(row),
                "source": row["source"],
            }
        )

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT pp.asset_id::text, a.hostname, a.os, a.os_version,
                       a.os_family, a.platform_profile, pp.package,
                       pp.current_version, pp.available_version, pp.checked_at
                FROM pending_packages pp
                JOIN assets a ON a.id = pp.asset_id
                WHERE a.status = 'ACTIVE'
                ORDER BY a.hostname, pp.package
                """
            )
            rows = cursor.fetchall()
    finally:
        connection.close()

    servers: dict[str, dict] = {}
    for (asset_id, hostname, os_name, os_version, os_family,
         profile, package, current, available, checked_at) in rows:
        server = servers.setdefault(
            asset_id,
            {
                "asset_id": asset_id,
                "hostname": hostname,
                "os": os_name,
                "os_version": os_version,
                "os_family": os_family,
                "platform_profile": profile,
                "checked_at": checked_at,
                "packages": [],
            },
        )
        cves = cves_by_asset_pkg.get((asset_id, package), [])
        cves.sort(key=lambda c: (c["exploitation"] != "exploited",
                                 c["severity"] != "critical"))
        server["packages"].append(
            {
                "name": package,
                "current_version": current,
                "available_version": available,
                "cves": cves,
                "exploited_count": sum(
                    1 for c in cves if c["exploitation"] == "exploited"
                ),
            }
        )

    result = list(servers.values())
    for server in result:
        server["exploited_count"] = sum(
            p["exploited_count"] for p in server["packages"]
        )
        server["security_count"] = sum(
            1 for p in server["packages"] if p["cves"]
        )
    result.sort(key=lambda s: (-s["exploited_count"], s["hostname"]))
    return result


def dashboard_summary() -> dict:
    """The Overview tiles, donuts and bars, computed from the fleet join."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (WHERE status = 'ACTIVE'),
                    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days'),
                    COUNT(*) FILTER (WHERE status <> 'ACTIVE')
                FROM assets
                """
            )
            total_assets, active_assets, new_30d, inactive_assets = cursor.fetchone()

            cursor.execute("SELECT COUNT(*) FROM pending_packages")
            pending_updates = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(DISTINCT asset_id) FROM pending_packages"
            )
            servers_with_pending = cursor.fetchone()[0]

            # Per active server: distro, scanned-at-least-once (the platform
            # profile is set on first discovery), and whether anything is
            # pending. Basis for fleet_status and by_distribution.
            cursor.execute(
                """
                SELECT a.id::text,
                       COALESCE(a.os, 'Unknown'),
                       a.platform_profile IS NOT NULL,
                       EXISTS (SELECT 1 FROM pending_packages pp
                               WHERE pp.asset_id = a.id)
                FROM assets a
                WHERE a.status = 'ACTIVE'
                """
            )
            server_rows = cursor.fetchall()

            # Most recent job status per asset (any age).
            cursor.execute(
                """
                SELECT DISTINCT ON (asset_id) asset_id::text, status
                FROM patch_jobs
                ORDER BY asset_id, created_at DESC
                """
            )
            last_job_status = dict(cursor.fetchall())

            # Job executions over the last 30 days.
            cursor.execute(
                """
                SELECT COUNT(*),
                       COUNT(*) FILTER (WHERE status = 'COMPLETED'),
                       COUNT(*) FILTER (WHERE status = 'FAILED'),
                       COUNT(*) FILTER (WHERE status IN ('CREATED', 'RUNNING'))
                FROM patch_jobs
                WHERE created_at > NOW() - INTERVAL '30 days'
                """
            )
            jobs_total, jobs_succeeded, jobs_failed, jobs_running = cursor.fetchone()

            # Servers whose most recent successful job reported that a reboot
            # is required. We cannot see whether the reboot has happened since;
            # this flags "patched, reboot reported needed by that job".
            cursor.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT DISTINCT ON (asset_id) reboot_required
                    FROM patch_jobs
                    WHERE status = 'COMPLETED'
                    ORDER BY asset_id, created_at DESC
                ) last_jobs
                WHERE reboot_required
                """
            )
            reboot_flagged = cursor.fetchone()[0]
    finally:
        connection.close()

    # One state per active server (disjoint buckets, worst wins):
    # not_scanned -> failed (last job) -> pending -> up_to_date
    fleet_status = {"up_to_date": 0, "pending": 0, "failed": 0, "not_scanned": 0}
    distros: dict[str, dict] = {}
    for asset_id, os_name, scanned, has_pending in server_rows:
        if not scanned:
            state = "not_scanned"
        elif last_job_status.get(asset_id) == "FAILED":
            state = "failed"
        elif has_pending:
            state = "pending"
        else:
            state = "up_to_date"
        fleet_status[state] += 1

        distro = distros.setdefault(
            os_name, {"os": os_name, "servers": 0, "compliant": 0}
        )
        distro["servers"] += 1
        if state == "up_to_date":
            distro["compliant"] += 1

    by_distribution = [
        {
            "os": d["os"],
            "servers": d["servers"],
            "compliant_pct": round(100 * d["compliant"] / d["servers"]),
        }
        for d in sorted(distros.values(), key=lambda d: -d["servers"])
    ]

    join_rows = _join_rows()
    security_packages = {(r["asset_id"], r["package"]) for r in join_rows}

    cves = fleet_cves()
    exploited = [c for c in cves if c["exploitation"] == "exploited"]
    exposed_servers = {
        s["asset_id"] for c in exploited for s in c["servers"]
    }

    by_severity: dict[str, dict] = {}
    for c in cves:
        bucket = by_severity.setdefault(
            c["severity"], {"severity": c["severity"], "count": 0, "exploited": 0}
        )
        bucket["count"] += 1
        if c["exploitation"] == "exploited":
            bucket["exploited"] += 1

    kev_due_7d = [
        c for c in cves
        if c["days_left"] is not None and 0 <= c["days_left"] <= 7
    ]
    kev_overdue = [
        c for c in cves
        if c["days_left"] is not None and c["days_left"] < 0
    ]

    patched_servers = max(active_assets - servers_with_pending, 0)

    return {
        "servers": {
            "total": total_assets,
            "active": active_assets,
            "new_30d": new_30d,
            "inactive": inactive_assets,
        },
        "fleet_status": fleet_status,
        "by_distribution": by_distribution,
        "jobs_30d": {
            "total": jobs_total,
            "succeeded": jobs_succeeded,
            "failed": jobs_failed,
            "running": jobs_running,
        },
        "reboot_flagged": reboot_flagged,
        "pending_updates": pending_updates,
        "security_updates": len(security_packages),
        "vulnerabilities": {
            "total": len(cves),
            "critical": sum(1 for c in cves if c["severity"] == "critical"),
            "exploited": len(exploited),
            "servers_exposed": len(exposed_servers),
        },
        "sla": {
            "kev_due_7d": len(kev_due_7d),
            "kev_overdue": len(kev_overdue),
        },
        "by_severity": sorted(
            by_severity.values(),
            key=lambda b: risk.SEVERITY_RANK.get(b["severity"], 0),
            reverse=True,
        ),
        # % of active servers with nothing pending at all
        "compliance_pct": round(100 * patched_servers / active_assets)
        if active_assets else 100,
    }


# ---------------------------------------------------------------- jobs


def cves_closed_by(asset_id: str, packages: list[str]) -> list[dict]:
    """Snapshot, at patch time, of the CVEs a set of package upgrades closes.

    Stored on the job so history keeps saying what was closed even after
    Zero-Day retention drops the records.
    """
    if not packages:
        return []

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT
                    pc.cve_id,
                    COALESCE(z.severity, pc.distro_severity, 'unknown'),
                    COALESCE(z.maturity, 'none'),
                    COALESCE(z.exploited, FALSE),
                    COALESCE(z.ransomware, FALSE),
                    COALESCE(z.kev, FALSE),
                    z.cve_id IS NOT NULL
                FROM package_cves pc
                JOIN assets a ON a.id = %s AND a.os_family = pc.os_family
                LEFT JOIN zeroday_cves z ON z.cve_id = pc.cve_id
                WHERE pc.package = ANY(%s)
                """,
                (asset_id, packages),
            )
            rows = cursor.fetchall()
    finally:
        connection.close()

    closed = [
        {
            "cve": cve_id,
            "severity": severity,
            "maturity": maturity,
            "exploited": exploited or maturity in risk.EXPLOITED_MATURITIES,
            "ransomware": ransomware,
            "kev": kev,
            "source": "zeroday" if tracked else "distro",
        }
        for cve_id, severity, maturity, exploited, ransomware, kev, tracked in rows
    ]
    closed.sort(key=lambda c: (not c["exploited"],
                               -risk.SEVERITY_RANK.get(c["severity"], 0)))
    return closed
