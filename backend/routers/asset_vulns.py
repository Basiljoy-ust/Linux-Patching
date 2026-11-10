"""A4 — GET /api/assets/{asset_id}/vulnerabilities.

The server view's Zero-Day exposure card and the "vulnerabilities fixed
by pending updates" table. Served from the stored join; run a patch
check (or POST /api/updates/refresh) first to populate it.
"""

from fastapi import APIRouter, HTTPException

from database import get_connection
from services import fleet_join

router = APIRouter()


@router.get("/api/assets/{asset_id}/vulnerabilities")
def asset_vulnerabilities(asset_id: str):
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT hostname FROM assets WHERE id = %s", (asset_id,)
            )
            asset = cursor.fetchone()
    finally:
        connection.close()

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    result = fleet_join.asset_vulnerabilities(asset_id)
    result["hostname"] = asset[0]
    return result
