from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from database import get_connection

import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from tempfile import TemporaryDirectory
from time import perf_counter


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)

api_logger = logging.getLogger("linux_patching.api")
api_logger.setLevel(logging.INFO)
api_logger.propagate = False

if not api_logger.handlers:
    file_handler = RotatingFileHandler(
        LOG_DIR / "api.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    api_logger.addHandler(file_handler)


app = FastAPI(
    title="Linux Patching API",
    version="1.0.0",
)

    
class PatchRequest(BaseModel):
    packages: list[str] = Field(
        min_length=1,
        max_length=50,
        description="Package names to patch"
    )


ANSIBLE_DIR = BASE_DIR / "ansible"
ANSIBLE_INVENTORY = ANSIBLE_DIR / "inventory.ini"
LOCAL_INVENTORY_HOSTS = {"localhost", "Linux-patching1"}
ANSIBLE_VAULT_PASSWORD_FILE = Path(
    os.environ.get(
        "ANSIBLE_VAULT_PASSWORD_FILE",
        str(Path.home() / ".config" / "linux-patching" / "vault-password"),
    )
)


@app.middleware("http")
async def log_api_request(request: Request, call_next):
    started_at = perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception:
        api_logger.exception(
            "request_failed method=%s path=%s",
            request.method,
            request.url.path,
        )
        raise
    finally:
        duration_ms = (perf_counter() - started_at) * 1000
        api_logger.info(
            "request method=%s path=%s status=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            status_code,
            duration_ms,
        )


def validate_ansible_credentials(hostname: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", hostname):
        raise HTTPException(
            status_code=409,
            detail="Asset hostname must match an Ansible inventory host",
        )

    if hostname in LOCAL_INVENTORY_HOSTS:
        return

    credentials_file = (
        ANSIBLE_DIR / "host_vars" / hostname / "vault.yml"
    )

    if not ANSIBLE_VAULT_PASSWORD_FILE.is_file():
        raise HTTPException(
            status_code=503,
            detail=(
                "Ansible Vault password file is not configured. "
                "See ansible/README.md to configure managed-host credentials."
            ),
        )

    if not credentials_file.is_file():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Encrypted Ansible credentials are not configured for "
                f"{hostname}. See ansible/README.md."
            ),
        )

    try:
        with credentials_file.open(encoding="utf-8") as file:
            is_encrypted = file.readline().startswith("$ANSIBLE_VAULT;")
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not read Ansible credentials for {hostname}",
        ) from exc

    if not is_encrypted:
        raise HTTPException(
            status_code=503,
            detail=f"Credentials for {hostname} must be encrypted with Ansible Vault",
        )


def ansible_vault_args(hostname: str) -> list[str]:
    if hostname in LOCAL_INVENTORY_HOSTS:
        return []
    return ["--vault-password-file", str(ANSIBLE_VAULT_PASSWORD_FILE)]


def discover_remote_patches(hostname: str) -> dict:
    validate_ansible_credentials(hostname)
    playbook = ANSIBLE_DIR / "patch_discovery.yml"
    started_at = perf_counter()

    api_logger.info(
        "patch_discovery_started target=%s inventory=%s",
        hostname,
        ANSIBLE_INVENTORY,
    )

    with TemporaryDirectory(prefix="linux-patching-discovery-") as output_dir:
        try:
            result = subprocess.run(
                [
                    "/usr/bin/ansible-playbook",
                    "-i",
                    str(ANSIBLE_INVENTORY),
                    str(playbook),
                    *ansible_vault_args(hostname),
                    "--limit",
                    hostname,
                    "-e",
                    f"patch_discovery_output_dir={output_dir}",
                ],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
                cwd=BASE_DIR,
            )
        except subprocess.TimeoutExpired as exc:
            api_logger.error(
                "patch_discovery_timed_out target=%s timeout_seconds=180 elapsed_ms=%.2f",
                hostname,
                (perf_counter() - started_at) * 1000,
            )
            raise HTTPException(
                status_code=504,
                detail="Remote patch discovery timed out",
            ) from exc

        if result.returncode != 0:
            api_logger.error(
                "patch_discovery_failed target=%s return_code=%s elapsed_ms=%.2f stderr=%s",
                hostname,
                result.returncode,
                (perf_counter() - started_at) * 1000,
                result.stderr.strip()[-2000:],
            )
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Remote patch discovery failed",
                    "error": result.stderr.strip()[-5000:],
                },
            )

        output_file = (
            Path(output_dir)
            / f"linux-patching-discovery-{hostname}.json"
        )

        try:
            discovery = json.loads(output_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            api_logger.exception(
                "patch_discovery_result_invalid target=%s",
                hostname,
            )
            raise HTTPException(
                status_code=502,
                detail="Could not read remote patch discovery results",
            ) from exc

        packages = discovery.get("packages", [])
        api_logger.info(
            "patch_discovery_completed target=%s checked_at=%s package_count=%s elapsed_ms=%.2f",
            hostname,
            discovery.get("checked_at", "unknown"),
            len(packages) if isinstance(packages, list) else "unknown",
            (perf_counter() - started_at) * 1000,
        )
        return discovery


def discover_running_services(hostname: str) -> dict[str, dict[str, str]]:
    validate_ansible_credentials(hostname)
    started_at = perf_counter()

    api_logger.info("service_discovery_started target=%s", hostname)

    if hostname in LOCAL_INVENTORY_HOSTS:
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(BASE_DIR / "telemetry" / "service_inventory.py"),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                cwd=BASE_DIR,
            )
        except subprocess.TimeoutExpired as exc:
            api_logger.error(
                "service_discovery_timed_out target=%s timeout_seconds=20 elapsed_ms=%.2f",
                hostname,
                (perf_counter() - started_at) * 1000,
            )
            raise HTTPException(
                status_code=504,
                detail="Local service discovery timed out",
            ) from exc

        if result.returncode != 0:
            api_logger.error(
                "service_discovery_failed target=%s return_code=%s stderr=%s",
                hostname,
                result.returncode,
                result.stderr.strip()[-2000:],
            )
            raise HTTPException(
                status_code=502,
                detail="Local service discovery failed",
            )

        try:
            services = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            api_logger.exception("service_discovery_result_invalid target=%s", hostname)
            raise HTTPException(
                status_code=502,
                detail="Local service discovery returned invalid JSON",
            ) from exc
    else:
        services = None

    if services is None:
        playbook = ANSIBLE_DIR / "services_discovery.yml"

        with TemporaryDirectory(prefix="linux-patching-services-") as output_dir:
            try:
                result = subprocess.run(
                    [
                        "/usr/bin/ansible-playbook",
                        "-i",
                        str(ANSIBLE_INVENTORY),
                        str(playbook),
                        *ansible_vault_args(hostname),
                        "--limit",
                        hostname,
                        "-e",
                        f"service_inventory_output_dir={output_dir}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                    cwd=BASE_DIR,
                )
            except subprocess.TimeoutExpired as exc:
                api_logger.error(
                    "service_discovery_timed_out target=%s timeout_seconds=45 elapsed_ms=%.2f",
                    hostname,
                    (perf_counter() - started_at) * 1000,
                )
                raise HTTPException(
                    status_code=504,
                    detail="Service discovery timed out",
                ) from exc

            if result.returncode != 0:
                api_logger.error(
                    "service_discovery_failed target=%s return_code=%s elapsed_ms=%.2f stderr=%s",
                    hostname,
                    result.returncode,
                    (perf_counter() - started_at) * 1000,
                    result.stderr.strip()[-2000:],
                )
                raise HTTPException(
                    status_code=502,
                    detail={
                        "message": "Service discovery failed",
                        "error": result.stderr.strip()[-5000:],
                    },
                )

            output_file = (
                Path(output_dir)
                / f"linux-patching-services-{hostname}.json"
            )
            try:
                services = json.loads(output_file.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                api_logger.exception(
                    "service_discovery_result_invalid target=%s",
                    hostname,
                )
                raise HTTPException(
                    status_code=502,
                    detail="Could not read service discovery results",
                ) from exc

    if not isinstance(services, dict) or any(
        not isinstance(service_data, dict)
        or not isinstance(service_data.get("status"), str)
        or not isinstance(service_data.get("enabled"), str)
        for service_data in services.values()
    ):
        raise HTTPException(
            status_code=502,
            detail="Service discovery returned an invalid response",
        )

    api_logger.info(
        "service_discovery_completed target=%s service_count=%s elapsed_ms=%.2f",
        hostname,
        len(services),
        (perf_counter() - started_at) * 1000,
    )
    return services


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/api/assets")
def get_assets():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    hostname,
                    ip_address,
                    username,
                    os,
                    os_version,
                    kernel_version,
                    status,
                    created_at,
                    updated_at
                FROM assets
                ORDER BY created_at DESC
                """
            )

            rows = cursor.fetchall()

            columns = [
                "id",
                "hostname",
                "ip_address",
                "username",
                "os",
                "os_version",
                "kernel_version",
                "status",
                "created_at",
                "updated_at",
            ]

            return [
                dict(zip(columns, row))
                for row in rows
            ]

    finally:
        connection.close()


@app.get("/api/assets/{asset_id}/telemetry")
def get_telemetry(asset_id: str):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    captured_at,
                    cpu_usage_percent,
                    memory_total_mb,
                    memory_used_mb,
                    memory_available_mb,
                    memory_usage_percent,
                    load_1m,
                    load_5m,
                    load_15m,
                    disk_total_gb,
                    disk_used_gb,
                    disk_free_gb,
                    disk_usage_percent,
                    network_data
                FROM telemetry_snapshots
                WHERE asset_id = %s
                ORDER BY captured_at DESC
                LIMIT 1
                """,
                (asset_id,),
            )

            row = cursor.fetchone()

            if row is None:
                raise HTTPException(
                    status_code=404,
                    detail="No telemetry found for this asset",
                )

            return {
                "captured_at": row[0],
                "cpu": {
                    "usage_percent": float(row[1]),
                },
                "memory": {
                    "total_mb": float(row[2]),
                    "used_mb": float(row[3]),
                    "available_mb": float(row[4]),
                    "usage_percent": float(row[5]),
                },
                "load": {
                    "1m": float(row[6]),
                    "5m": float(row[7]),
                    "15m": float(row[8]),
                },
                "disk": {
                    "total_gb": float(row[9]),
                    "used_gb": float(row[10]),
                    "free_gb": float(row[11]),
                    "usage_percent": float(row[12]),
                },
                "network": row[13],
            }

    finally:
        connection.close()


@app.get("/api/assets/{asset_id}/services")
def get_services(asset_id: str):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT hostname, status
                FROM assets
                WHERE id = %s
                """,
                (asset_id,),
            )
            asset = cursor.fetchone()

    finally:
        connection.close()

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset[1].upper() != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail=f"Asset is not active: {asset[1]}",
        )

    services = discover_running_services(asset[0])
    captured_at = datetime.now(timezone.utc).isoformat()

    return [
        {
            "captured_at": captured_at,
            "service": service_name,
            "status": service_data["status"],
            "enabled": service_data["enabled"],
        }
        for service_name, service_data in sorted(services.items())
    ]


@app.get("/api/assets/{asset_id}/telemetry/history")
def get_telemetry_history(
    asset_id: str,
    limit: int = 50,
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 500",
        )

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    captured_at,
                    cpu_usage_percent,
                    memory_usage_percent,
                    load_1m,
                    load_5m,
                    load_15m,
                    disk_usage_percent
                FROM telemetry_snapshots
                WHERE asset_id = %s
                ORDER BY captured_at DESC
                LIMIT %s
                """,
                (asset_id, limit),
            )

            rows = cursor.fetchall()

            return [
                {
                    "captured_at": row[0],
                    "cpu_usage_percent": float(row[1]),
                    "memory_usage_percent": float(row[2]),
                    "load": {
                        "1m": float(row[3]),
                        "5m": float(row[4]),
                        "15m": float(row[5]),
                    },
                    "disk_usage_percent": float(row[6]),
                }
                for row in rows
            ]

    finally:
        connection.close()


@app.post("/api/assets/{asset_id}/patch-check")
def check_patches(asset_id: str):

    connection = get_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    hostname,
                    os,
                    os_version,
                    status
                FROM assets
                WHERE id = %s
                """,
                (asset_id,),
            )

            asset = cursor.fetchone()

            if asset is None:
                raise HTTPException(
                    status_code=404,
                    detail="Asset not found",
                )

            if asset[4].upper() != "ACTIVE":
                raise HTTPException(
                    status_code=409,
                    detail=f"Asset is not active: {asset[4]}",
                )

    finally:
        connection.close()

    api_logger.info(
        "patch_check_requested asset_id=%s target=%s os=%s os_version=%s",
        asset_id,
        asset[1],
        asset[2],
        asset[3],
    )
    discovery = discover_remote_patches(asset[1])

    return {
        "asset_id": asset_id,
        "hostname": asset[1],
        "os": asset[2],
        "os_version": asset[3],
        "patch_check": discovery,
    }


@app.post("/api/assets/{asset_id}/patch-jobs")
def create_patch_job(
    asset_id: str,
    request: PatchRequest,
):
    """
    Create and execute a patch job.

    Lifecycle:
        CREATED -> RUNNING -> COMPLETED
                           -> FAILED
    """

    # ---------------------------------------------------------
    # 1. Validate asset
    # ---------------------------------------------------------

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    hostname,
                    status
                FROM assets
                WHERE id = %s
                """,
                (asset_id,),
            )

            asset = cursor.fetchone()

            if asset is None:
                raise HTTPException(
                    status_code=404,
                    detail="Asset not found",
                )

            if asset[2].upper() != "ACTIVE":
                raise HTTPException(
                    status_code=409,
                    detail=f"Asset is not active: {asset[2]}",
                )

    finally:
        connection.close()

    # ---------------------------------------------------------
    # 2. Discover currently upgradeable packages on the selected server
    # ---------------------------------------------------------

    discovery = discover_remote_patches(asset[1])

    # ---------------------------------------------------------
    # 3. Validate requested packages
    # ---------------------------------------------------------

    available_packages = {
        package["name"]
        for package in discovery.get("packages", [])
    }

    requested_packages = set(request.packages)

    invalid_packages = (
        requested_packages - available_packages
    )

    if invalid_packages:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "One or more packages are not currently upgradeable",
                "invalid_packages": sorted(invalid_packages),
                "available_packages": sorted(available_packages),
            },
        )

    # ---------------------------------------------------------
    # 4. Create patch job
    # ---------------------------------------------------------

    connection = get_connection()

    try:
        with connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    INSERT INTO patch_jobs (
                        asset_id,
                        status
                    )
                    VALUES (
                        %s,
                        %s
                    )
                    RETURNING id, created_at
                    """,
                    (
                        asset_id,
                        "CREATED",
                    ),
                )

                job = cursor.fetchone()

                job_id = job[0]
                created_at = job[1]

                cursor.execute(
                    """
                    INSERT INTO patch_events (
                        patch_job_id,
                        event_type,
                        event_status,
                        message,
                        event_data
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        job_id,
                        "PATCH_REQUESTED",
                        "SUCCESS",
                        "Patch job created",
                        json.dumps({
                            "packages": sorted(requested_packages)
                        }),
                    ),
                )

    finally:
        connection.close()

    # ---------------------------------------------------------
    # 5. Mark job RUNNING
    # ---------------------------------------------------------

    connection = get_connection()

    try:
        with connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE patch_jobs
                    SET
                        status = %s,
                        started_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        "RUNNING",
                        job_id,
                    ),
                )

                cursor.execute(
                    """
                    INSERT INTO patch_events (
                        patch_job_id,
                        event_type,
                        event_status,
                        message
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        job_id,
                        "PATCH_STARTED",
                        "RUNNING",
                        "Ansible patch execution started",
                    ),
                )

    finally:
        connection.close()

    # ---------------------------------------------------------
    # 6. Execute Ansible
    # ---------------------------------------------------------

    playbook = (
        BASE_DIR
        / "ansible"
        / "patch_execute.yml"
    )

    extra_vars = json.dumps(
        {
            "patch_packages": sorted(
                requested_packages
            )
        }
    )

    try:
        result = subprocess.run(
            [
                "/usr/bin/ansible-playbook",
                "-i",
                str(ANSIBLE_INVENTORY),
                str(playbook),
                *ansible_vault_args(asset[1]),
                "--limit",
                asset[1],
                "-e",
                extra_vars,
            ],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
            cwd=BASE_DIR,
        )

    except subprocess.TimeoutExpired:

        connection = get_connection()

        try:
            with connection:
                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        UPDATE patch_jobs
                        SET
                            status = %s,
                            completed_at = NOW(),
                            success = FALSE,
                            failure_reason = %s
                        WHERE id = %s
                        """,
                        (
                            "FAILED",
                            "Patch execution timed out",
                            job_id,
                        ),
                    )

                    cursor.execute(
                        """
                        INSERT INTO patch_events (
                            patch_job_id,
                            event_type,
                            event_status,
                            message
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            job_id,
                            "PATCH_FAILED",
                            "FAILED",
                            "Patch execution timed out",
                        ),
                    )

        finally:
            connection.close()

        raise HTTPException(
            status_code=504,
            detail={
                "job_id": str(job_id),
                "message": "Patch execution timed out",
            },
        )

    # ---------------------------------------------------------
    # 7. Process Ansible result
    # ---------------------------------------------------------

    if result.returncode != 0:

        failure_reason = result.stderr.strip()

        if not failure_reason:
            failure_reason = "Ansible patch execution failed"

        connection = get_connection()

        try:
            with connection:
                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        UPDATE patch_jobs
                        SET
                            status = %s,
                            completed_at = NOW(),
                            success = FALSE,
                            failure_reason = %s
                        WHERE id = %s
                        """,
                        (
                            "FAILED",
                            failure_reason[-5000:],
                            job_id,
                        ),
                    )

                    cursor.execute(
                        """
                        INSERT INTO patch_events (
                            patch_job_id,
                            event_type,
                            event_status,
                            message,
                            event_data
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            job_id,
                            "PATCH_FAILED",
                            "FAILED",
                            "Ansible patch execution failed",
                            json.dumps({
                                "stdout": result.stdout[-5000:],
                                "stderr": result.stderr[-5000:],
                            }),
                        ),
                    )

        finally:
            connection.close()

        raise HTTPException(
            status_code=500,
            detail={
                "job_id": str(job_id),
                "message": "Patch execution failed",
                "stdout": result.stdout[-5000:],
                "stderr": result.stderr[-5000:],
            },
        )

    # ---------------------------------------------------------
    # 8. Mark job COMPLETED
    # ---------------------------------------------------------

    connection = get_connection()

    try:
        with connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE patch_jobs
                    SET
                        status = %s,
                        completed_at = NOW(),
                        success = TRUE
                    WHERE id = %s
                    """,
                    (
                        "COMPLETED",
                        job_id,
                    ),
                )

                cursor.execute(
                    """
                    INSERT INTO patch_events (
                        patch_job_id,
                        event_type,
                        event_status,
                        message,
                        event_data
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        job_id,
                        "PATCH_COMPLETED",
                        "SUCCESS",
                        "Patch execution completed successfully",
                        json.dumps({
                            "packages": sorted(requested_packages),
                            "ansible_output": result.stdout[-10000:],
                        }),
                    ),
                )

    finally:
        connection.close()

    return {
        "job_id": str(job_id),
        "asset_id": asset_id,
        "hostname": asset[1],
        "status": "COMPLETED",
        "success": True,
        "packages": sorted(requested_packages),
        "created_at": created_at,
        "ansible_output": result.stdout[-10000:],
    }
