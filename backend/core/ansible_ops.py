"""Ansible operations: credential checks, discovery and result parsing.

Moved out of main.py unchanged (refactor/split-backend).
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from fastapi import HTTPException

from database import get_connection
from platform_profiles import is_supported, normalize_profile, profile_info

from core.config import (
    ANSIBLE_DIR,
    ANSIBLE_INVENTORY,
    ANSIBLE_VAULT_PASSWORD_FILE,
    BASE_DIR,
    DISCOVERY_TIMEOUT_SECONDS,
    LOCAL_INVENTORY_HOSTS,
    api_logger,
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
                timeout=DISCOVERY_TIMEOUT_SECONDS,
                check=False,
                cwd=BASE_DIR,
            )
        except subprocess.TimeoutExpired as exc:
            api_logger.error(
                "patch_discovery_timed_out target=%s timeout_seconds=%s elapsed_ms=%.2f",
                hostname,
                DISCOVERY_TIMEOUT_SECONDS,
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


def persist_platform(asset_id: str, discovery: dict) -> str:
    """Store the detected platform on the asset and return the profile.

    Anything that is not a supported profile is stored as 'unsupported'.
    """
    profile = normalize_profile(discovery.get("platform_profile"))
    os_family, _ = profile_info(profile)

    connection = get_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE assets
                    SET
                        os_family = %s,
                        platform_profile = %s,
                        updated_at = NOW()
                    WHERE id = %s
                      AND (
                        os_family IS DISTINCT FROM %s
                        OR platform_profile IS DISTINCT FROM %s
                      )
                    """,
                    (os_family, profile, asset_id, os_family, profile),
                )
    finally:
        connection.close()

    return profile


def require_supported_platform(asset_id: str, hostname: str, discovery: dict) -> str:
    profile = persist_platform(asset_id, discovery)

    if not is_supported(profile):
        api_logger.warning(
            "platform_unsupported asset_id=%s target=%s detected=%s",
            asset_id,
            hostname,
            discovery.get("platform_profile"),
        )
        raise HTTPException(
            status_code=409,
            detail="Platform not supported",
        )

    return profile


def read_patch_result(output_dir: str, hostname: str) -> dict:
    """Read the machine-readable result written by patch_execute.yml."""
    result_file = Path(output_dir) / f"linux-patching-result-{hostname}.json"

    try:
        data = json.loads(result_file.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        api_logger.warning("patch_result_unreadable target=%s", hostname)
        return {}


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
