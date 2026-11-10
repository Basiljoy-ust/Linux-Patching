"""Per-asset patch discovery and execution endpoints.

Moved out of main.py unchanged (refactor/split-backend).
"""

import json
import subprocess
from tempfile import TemporaryDirectory

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

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

router = APIRouter()


class PatchRequest(BaseModel):
    packages: list[str] = Field(
        min_length=1,
        max_length=50,
        description="Package names to patch"
    )


@router.post("/api/assets/{asset_id}/patch-check")
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
    profile = require_supported_platform(asset_id, asset[1], discovery)

    return {
        "asset_id": asset_id,
        "hostname": asset[1],
        "os": asset[2],
        "os_version": asset[3],
        "os_family": profile_info(profile)[0],
        "platform_profile": profile,
        "patch_check": discovery,
    }


@router.post("/api/assets/{asset_id}/patch-jobs")
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
    platform_profile = require_supported_platform(asset_id, asset[1], discovery)
    os_family, package_manager = profile_info(platform_profile)

    # ---------------------------------------------------------
    # 3. Validate requested packages
    # ---------------------------------------------------------

    # Architecture suffixes are stripped on both sides so "openssl" and
    # "openssl.x86_64" both match the discovered "openssl.x86_64".
    available_packages = {
        normalize_package_name(package["name"], package_manager)
        for package in discovery.get("packages", [])
    }

    requested_packages = {
        normalize_package_name(name, package_manager)
        for name in request.packages
    }

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
                        status,
                        package_manager
                    )
                    VALUES (
                        %s,
                        %s,
                        %s
                    )
                    RETURNING id, created_at
                    """,
                    (
                        asset_id,
                        "CREATED",
                        package_manager,
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

    result_dir = TemporaryDirectory(prefix="linux-patching-result-")

    extra_vars = json.dumps(
        {
            "patch_packages": sorted(
                requested_packages
            ),
            "patch_result_output_dir": result_dir.name,
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
            timeout=PATCH_JOB_TIMEOUT_SECONDS,
            check=False,
            cwd=BASE_DIR,
        )

    except subprocess.TimeoutExpired:
        result_dir.cleanup()

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

    patch_result = read_patch_result(result_dir.name, asset[1])
    result_dir.cleanup()

    # None when the playbook could not report it (never guessed as False).
    reboot_required = patch_result.get("reboot_required")

    if result.returncode != 0:

        # Ansible usually reports task failures (including RHEL preflight
        # assertions) on stdout, so fall back to it when stderr is empty.
        failure_reason = (
            result.stderr.strip()
            or result.stdout.strip()
        )

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
                        success = TRUE,
                        reboot_required = %s
                    WHERE id = %s
                    """,
                    (
                        "COMPLETED",
                        reboot_required,
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
                            "reboot_required": reboot_required,
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
        "os_family": os_family,
        "platform_profile": platform_profile,
        "reboot_required": reboot_required,
        "created_at": created_at,
        "ansible_output": result.stdout[-10000:],
    }
