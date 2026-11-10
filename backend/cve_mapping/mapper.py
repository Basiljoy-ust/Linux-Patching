"""Builds and maintains the package_cves table.

Two feeders:
- refresh_for_discovery(): called right after patch discovery persists a
  host's pending packages — RHEL rows come from the discovery's own
  updateinfo output; Ubuntu rows from OSV.
- refresh_missing(): called from the sync loop — fills in Ubuntu packages
  that still have no mapping (e.g. pending rows that predate this code).
"""

from database import get_connection
from core.config import api_logger

from cve_mapping import rhel, ubuntu

# Re-check a package's mapping after this many days.
STALE_DAYS = 7
# Cap OSV work per sync cycle.
MISSING_BATCH = 50


def _upsert(rows: list[tuple]) -> None:
    """rows: (os_family, package, version, cve_id, fixed_version,
    distro_severity, source)"""
    if not rows:
        return
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO package_cves (
                        os_family, package, version, cve_id,
                        fixed_version, distro_severity, source, updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (os_family, package, cve_id) DO UPDATE SET
                        version = EXCLUDED.version,
                        fixed_version = COALESCE(EXCLUDED.fixed_version,
                                                 package_cves.fixed_version),
                        distro_severity = COALESCE(EXCLUDED.distro_severity,
                                                   package_cves.distro_severity),
                        source = EXCLUDED.source,
                        updated_at = NOW()
                    """,
                    rows,
                )
    finally:
        connection.close()


def refresh_for_discovery(discovery: dict) -> int:
    """Map one host's discovery result into package_cves. Returns row count.

    Never raises: mapping failures must not fail a patch check.
    """
    try:
        os_family = discovery.get("os_family")
        packages = discovery.get("packages") or []

        rows: list[tuple] = []

        if os_family == "RedHat":
            for entry in rhel.parse_updateinfo(discovery.get("updateinfo_cve") or ""):
                rows.append(
                    (
                        "RedHat",
                        entry["package"],
                        None,
                        entry["cve_id"],
                        entry["fixed_version"],
                        entry["distro_severity"],
                        "updateinfo",
                    )
                )

        elif os_family == "Debian":
            mapping = ubuntu.map_packages(packages)
            versions = {p["name"]: p.get("current_version") for p in packages}
            for package, cves in mapping.items():
                for cve_id in cves:
                    rows.append(
                        ("Debian", package, versions.get(package),
                         cve_id, None, None, "osv")
                    )

        _upsert(rows)
        if os_family == "Debian":
            _mark_checked([p["name"] for p in packages if p.get("name")])
        return len(rows)

    except Exception:
        api_logger.exception("cve_mapping_discovery_failed")
        return 0


def _mark_checked(packages: list[str], os_family: str = "Debian") -> None:
    if not packages:
        return
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO package_cve_checks (os_family, package, checked_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (os_family, package) DO UPDATE SET checked_at = NOW()
                    """,
                    [(os_family, package) for package in packages],
                )
    finally:
        connection.close()


def refresh_missing(limit: int = MISSING_BATCH) -> int:
    """Map pending Debian packages not looked up in the last STALE_DAYS.

    A lookup that finds no CVEs still counts as done (package_cve_checks),
    so clean packages are not re-queried every cycle.
    """
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT pp.package, pp.current_version
                FROM pending_packages pp
                JOIN assets a ON a.id = pp.asset_id
                WHERE a.os_family = 'Debian'
                  AND NOT EXISTS (
                      SELECT 1 FROM package_cve_checks c
                      WHERE c.os_family = 'Debian'
                        AND c.package = pp.package
                        AND c.checked_at > NOW() - make_interval(days => %s)
                  )
                LIMIT %s
                """,
                (STALE_DAYS, limit),
            )
            todo = cursor.fetchall()
    finally:
        connection.close()

    if not todo:
        return 0

    packages = [{"name": name, "current_version": version} for name, version in todo]
    mapping = ubuntu.map_packages(packages)
    versions = dict(todo)

    rows = [
        ("Debian", package, versions.get(package), cve_id, None, None, "osv")
        for package, cves in mapping.items()
        for cve_id in cves
    ]
    _upsert(rows)
    _mark_checked([name for name, _ in todo])
    return len(packages)
