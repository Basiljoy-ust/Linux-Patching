"""Asset read endpoints: inventory, telemetry, services, history.

Moved out of main.py unchanged (refactor/split-backend).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from database import get_connection
from platform_profiles import profile_info

from core.ansible_ops import discover_running_services

router = APIRouter()


@router.get("/api/assets")
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
                    updated_at,
                    os_family,
                    platform_profile
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
                "os_family",
                "platform_profile",
            ]

            assets = []

            for row in rows:
                asset = dict(zip(columns, row))
                asset["package_manager"] = profile_info(
                    asset["platform_profile"]
                )[1]
                assets.append(asset)

            return assets

    finally:
        connection.close()


@router.get("/api/assets/{asset_id}/telemetry")
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


@router.get("/api/assets/{asset_id}/services")
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


@router.get("/api/assets/{asset_id}/telemetry/history")
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
