"""Multi-server patch jobs, run in a background thread.

POST /api/patch-jobs creates a patch_job_groups row plus one patch_jobs
row per target server, then returns immediately; a daemon thread works
through the servers one at a time with the same Ansible playbook the
single-server endpoint uses. GET /api/patch-jobs/{id} reports progress.

When a server completes, its packages leave pending_packages and the
CVEs they closed are snapshotted onto the job (fleet_join.cves_closed_by)
so History keeps its numbers after Zero-Day retention drops the records.
"""

import json
import subprocess
import threading
from tempfile import TemporaryDirectory

from database import get_connection
from platform_profiles import normalize_package_name, profile_info

from core.ansible_ops import (
    ansible_vault_args,
    discover_remote_patches,
    read_patch_result,
    require_supported_platform,
)
from core.config import (
    ANSIBLE_INVENTORY,
    BASE_DIR,
    PATCH_JOB_TIMEOUT_SECONDS,
    api_logger,
)
from services import fleet_join


# ---------------------------------------------------------------- helpers


def _event(cursor, job_id, event_type, status, message, data=None):
    cursor.execute(
        """
        INSERT INTO patch_events (patch_job_id, event_type, event_status,
                                  message, event_data)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (job_id, event_type, status, message,
         json.dumps(data) if data is not None else None),
    )


def _update_job(job_id, status, *, success=None, failure_reason=None,
                reboot_required=None, cves_closed=None, started=False):
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE patch_jobs SET
                        status = %s,
                        started_at = CASE WHEN %s THEN NOW() ELSE started_at END,
                        completed_at = CASE WHEN %s IN ('COMPLETED', 'FAILED')
                                            THEN NOW() ELSE completed_at END,
                        success = COALESCE(%s, success),
                        failure_reason = COALESCE(%s, failure_reason),
                        reboot_required = COALESCE(%s, reboot_required),
                        cves_closed = COALESCE(%s, cves_closed)
                    WHERE id = %s
                    """,
                    (status, started, status, success, failure_reason,
                     reboot_required,
                     json.dumps(cves_closed) if cves_closed is not None else None,
                     job_id),
                )
    finally:
        connection.close()


# ---------------------------------------------------------------- execution


def _run_one(job_id: str, asset_id: str, hostname: str,
             packages: list[str]) -> dict:
    """Patch one server. Returns {success, cves_closed, failure_reason?}."""
    _update_job(job_id, "RUNNING", started=True)

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                _event(cursor, job_id, "PATCH_STARTED", "RUNNING",
                       "Ansible patch execution started")
    finally:
        connection.close()

    try:
        discovery = discover_remote_patches(hostname)
        profile = require_supported_platform(asset_id, hostname, discovery)
        _, package_manager = profile_info(profile)
    except Exception as exc:  # HTTPException from helpers included
        reason = getattr(exc, "detail", str(exc))
        reason = reason if isinstance(reason, str) else json.dumps(reason)
        _update_job(job_id, "FAILED", success=False,
                    failure_reason=reason[:5000])
        return {"success": False, "failure_reason": reason}

    available = {
        normalize_package_name(p["name"], package_manager)
        for p in discovery.get("packages", [])
    }
    requested = {normalize_package_name(name, package_manager) for name in packages}
    valid = sorted(requested & available)
    skipped = sorted(requested - available)

    if not valid:
        reason = "No requested package is currently upgradeable"
        _update_job(job_id, "FAILED", success=False, failure_reason=reason)
        return {"success": False, "failure_reason": reason, "skipped": skipped}

    result_dir = TemporaryDirectory(prefix="linux-patching-result-")
    extra_vars = json.dumps(
        {"patch_packages": valid, "patch_result_output_dir": result_dir.name}
    )

    try:
        result = subprocess.run(
            [
                "/usr/bin/ansible-playbook",
                "-i", str(ANSIBLE_INVENTORY),
                str(BASE_DIR / "ansible" / "patch_execute.yml"),
                *ansible_vault_args(hostname),
                "--limit", hostname,
                "-e", extra_vars,
            ],
            capture_output=True,
            text=True,
            timeout=PATCH_JOB_TIMEOUT_SECONDS,
            check=False,
            cwd=BASE_DIR,
        )
    except subprocess.TimeoutExpired:
        result_dir.cleanup()
        _update_job(job_id, "FAILED", success=False,
                    failure_reason="Patch execution timed out")
        return {"success": False, "failure_reason": "Patch execution timed out"}

    patch_result = read_patch_result(result_dir.name, hostname)
    result_dir.cleanup()
    reboot_required = patch_result.get("reboot_required")

    if result.returncode != 0:
        reason = (result.stderr.strip() or result.stdout.strip()
                  or "Ansible patch execution failed")
        connection = get_connection()
        try:
            with connection:
                with connection.cursor() as cursor:
                    _event(cursor, job_id, "PATCH_FAILED", "FAILED",
                           "Ansible patch execution failed",
                           {"stdout": result.stdout[-5000:],
                            "stderr": result.stderr[-5000:]})
        finally:
            connection.close()
        _update_job(job_id, "FAILED", success=False,
                    failure_reason=reason[-5000:])
        return {"success": False, "failure_reason": reason[-5000:]}

    cves_closed = fleet_join.cves_closed_by(asset_id, valid)
    fleet_join.remove_pending_packages(asset_id, valid)

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                _event(cursor, job_id, "PATCH_COMPLETED", "SUCCESS",
                       "Patch execution completed successfully",
                       {"packages": valid, "skipped": skipped,
                        "reboot_required": reboot_required,
                        "cves_closed": [c["cve"] for c in cves_closed]})
    finally:
        connection.close()

    _update_job(job_id, "COMPLETED", success=True,
                reboot_required=reboot_required, cves_closed=cves_closed)
    return {"success": True, "cves_closed": cves_closed, "skipped": skipped}


def _run_group(group_id: str, jobs: list[dict]) -> None:
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE patch_job_groups SET status = 'RUNNING',"
                    " started_at = NOW() WHERE id = %s",
                    (group_id,),
                )
    finally:
        connection.close()

    all_closed: dict[str, dict] = {}
    successes = 0

    for job in jobs:
        try:
            outcome = _run_one(
                job["job_id"], job["asset_id"], job["hostname"], job["packages"]
            )
        except Exception:
            api_logger.exception(
                "patch_group_job_crashed group=%s job=%s", group_id, job["job_id"]
            )
            _update_job(job["job_id"], "FAILED", success=False,
                        failure_reason="Internal error during patch execution")
            continue

        if outcome.get("success"):
            successes += 1
            for closed in outcome.get("cves_closed") or []:
                all_closed[closed["cve"]] = closed

    status = (
        "COMPLETED" if successes == len(jobs)
        else "PARTIAL" if successes else "FAILED"
    )

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE patch_job_groups
                    SET status = %s, completed_at = NOW(), cves_closed = %s
                    WHERE id = %s
                    """,
                    (status, json.dumps(sorted(
                        all_closed.values(),
                        key=lambda c: (not c["exploited"], c["cve"]),
                    )), group_id),
                )
    finally:
        connection.close()

    api_logger.info(
        "patch_group_finished group=%s status=%s servers=%s cves_closed=%s",
        group_id, status, len(jobs), len(all_closed),
    )


# ---------------------------------------------------------------- public


def create_group(targets: list[dict]) -> dict:
    """targets: [{asset_id, packages[]}] — validated by the router.

    Creates the group + per-asset jobs and starts the worker thread.
    """
    asset_ids = [t["asset_id"] for t in targets]

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id::text, hostname, status
                FROM assets WHERE id = ANY(%s::uuid[])
                """,
                (asset_ids,),
            )
            assets = {row[0]: {"hostname": row[1], "status": row[2]}
                      for row in cursor.fetchall()}
    finally:
        connection.close()

    missing = [a for a in asset_ids if a not in assets]
    inactive = [a for a in asset_ids
                if a in assets and assets[a]["status"].upper() != "ACTIVE"]
    if missing or inactive:
        return {"error": {"missing": missing, "inactive": inactive}}

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO patch_job_groups (status, targets)
                    VALUES ('CREATED', %s)
                    RETURNING id::text, created_at
                    """,
                    (json.dumps(targets),),
                )
                group_id, created_at = cursor.fetchone()

                jobs = []
                for target in targets:
                    cursor.execute(
                        """
                        INSERT INTO patch_jobs (asset_id, status, group_id,
                                                requested_packages)
                        VALUES (%s, 'CREATED', %s, %s)
                        RETURNING id::text
                        """,
                        (target["asset_id"], group_id,
                         json.dumps(sorted(set(target["packages"])))),
                    )
                    job_id = cursor.fetchone()[0]
                    _event(cursor, job_id, "PATCH_REQUESTED", "SUCCESS",
                           "Patch job created",
                           {"packages": sorted(set(target["packages"])),
                            "group_id": group_id})
                    jobs.append(
                        {
                            "job_id": job_id,
                            "asset_id": target["asset_id"],
                            "hostname": assets[target["asset_id"]]["hostname"],
                            "packages": sorted(set(target["packages"])),
                        }
                    )
    finally:
        connection.close()

    thread = threading.Thread(
        target=_run_group, args=(group_id, jobs),
        name=f"patch-group-{group_id[:8]}", daemon=True,
    )
    thread.start()

    return {
        "job_id": group_id,
        "status": "CREATED",
        "created_at": created_at,
        "servers": len(jobs),
    }


def get_job(job_id: str) -> dict | None:
    """One group (preferred) or one legacy single job, with its results."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id::text, status, targets, cves_closed,
                       created_at, started_at, completed_at
                FROM patch_job_groups WHERE id::text = %s
                """,
                (job_id,),
            )
            group = cursor.fetchone()

            if group:
                cursor.execute(
                    """
                    SELECT j.id::text, j.asset_id::text, a.hostname, j.status,
                           j.success, j.reboot_required, j.failure_reason,
                           j.requested_packages, j.cves_closed
                    FROM patch_jobs j
                    JOIN assets a ON a.id = j.asset_id
                    WHERE j.group_id::text = %s
                    ORDER BY a.hostname
                    """,
                    (job_id,),
                )
                results = [
                    {
                        "job_id": row[0],
                        "asset_id": row[1],
                        "hostname": row[2],
                        "status": row[3],
                        "success": row[4],
                        "reboot_required": row[5],
                        "failure_reason": row[6],
                        "packages": row[7] or [],
                        "cves_closed": row[8] or [],
                    }
                    for row in cursor.fetchall()
                ]
                done = sum(1 for r in results
                           if r["status"] in ("COMPLETED", "FAILED"))
                return {
                    "job_id": group[0],
                    "kind": "group",
                    "status": group[1],
                    "targets": group[2],
                    "cves_closed": group[3] or [],
                    "created_at": group[4],
                    "started_at": group[5],
                    "completed_at": group[6],
                    "progress": {"done": done, "total": len(results)},
                    "results": results,
                }

            cursor.execute(
                """
                SELECT j.id::text, j.asset_id::text, a.hostname, j.status,
                       j.success, j.reboot_required, j.failure_reason,
                       j.requested_packages, j.cves_closed, j.created_at,
                       j.started_at, j.completed_at, j.package_manager
                FROM patch_jobs j
                JOIN assets a ON a.id = j.asset_id
                WHERE j.id::text = %s
                """,
                (job_id,),
            )
            row = cursor.fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return {
        "job_id": row[0],
        "kind": "single",
        "status": row[3],
        "created_at": row[9],
        "started_at": row[10],
        "completed_at": row[11],
        "cves_closed": row[8] or [],
        "results": [
            {
                "job_id": row[0],
                "asset_id": row[1],
                "hostname": row[2],
                "status": row[3],
                "success": row[4],
                "reboot_required": row[5],
                "failure_reason": row[6],
                "packages": row[7] or [],
                "cves_closed": row[8] or [],
            }
        ],
    }


def list_jobs(limit: int = 50) -> list[dict]:
    """History: groups plus pre-existing single jobs, newest first."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT g.id::text, g.status, g.created_at, g.completed_at,
                       g.cves_closed,
                       (SELECT COUNT(*) FROM patch_jobs j
                        WHERE j.group_id = g.id) AS servers,
                       g.targets
                FROM patch_job_groups g
                ORDER BY g.created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            groups = cursor.fetchall()

            cursor.execute(
                """
                SELECT j.id::text, j.status, j.created_at, j.completed_at,
                       j.cves_closed, a.hostname, j.requested_packages
                FROM patch_jobs j
                JOIN assets a ON a.id = j.asset_id
                WHERE j.group_id IS NULL
                ORDER BY j.created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            singles = cursor.fetchall()
    finally:
        connection.close()

    items = []

    for gid, status, created_at, completed_at, closed, servers, targets in groups:
        closed = closed or []
        items.append(
            {
                "job_id": gid,
                "kind": "group",
                "status": status,
                "created_at": created_at,
                "completed_at": completed_at,
                "servers": servers,
                "packages": sum(
                    len(t.get("packages") or []) for t in (targets or [])
                ),
                "cves_closed": len(closed),
                "exploited_closed": sum(1 for c in closed if c.get("exploited")),
            }
        )

    for jid, status, created_at, completed_at, closed, hostname, packages in singles:
        closed = closed or []
        items.append(
            {
                "job_id": jid,
                "kind": "single",
                "status": status,
                "created_at": created_at,
                "completed_at": completed_at,
                "servers": 1,
                "hostname": hostname,
                "packages": len(packages or []),
                "cves_closed": len(closed),
                "exploited_closed": sum(1 for c in closed if c.get("exploited")),
            }
        )

    items.sort(key=lambda i: i["created_at"], reverse=True)
    return items[:limit]
