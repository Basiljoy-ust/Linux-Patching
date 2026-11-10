"""A5 — the Updates view.

GET  /api/updates/pending  -> every active server's pending packages,
                              each with the CVEs its upgrade addresses
POST /api/updates/refresh  -> run patch discovery across the fleet in a
                              background thread (one server at a time)
"""

import threading

from fastapi import APIRouter

from database import get_connection
from core.ansible_ops import discover_remote_patches, persist_platform
from core.config import api_logger
from cve_mapping import mapper
from services import fleet_join

router = APIRouter()

_refresh_lock = threading.Lock()
_refresh_running = False


@router.get("/api/updates/pending")
def pending_updates():
    return fleet_join.pending_by_server()


def _refresh_fleet() -> None:
    global _refresh_running

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id::text, hostname FROM assets WHERE status = 'ACTIVE'"
            )
            assets = cursor.fetchall()
    finally:
        connection.close()

    try:
        for asset_id, hostname in assets:
            try:
                discovery = discover_remote_patches(hostname)
                persist_platform(asset_id, discovery)
                fleet_join.save_pending_packages(asset_id, discovery)
                mapper.refresh_for_discovery(discovery)
            except Exception as exc:
                api_logger.warning(
                    "fleet_refresh_host_failed target=%s error=%s",
                    hostname, getattr(exc, "detail", exc),
                )
        api_logger.info("fleet_refresh_completed servers=%s", len(assets))
    finally:
        with _refresh_lock:
            _refresh_running = False


@router.post("/api/updates/refresh", status_code=202)
def refresh_pending():
    global _refresh_running
    with _refresh_lock:
        if _refresh_running:
            return {"started": False, "message": "A fleet refresh is already running"}
        _refresh_running = True

    thread = threading.Thread(
        target=_refresh_fleet, name="fleet-refresh", daemon=True
    )
    thread.start()
    return {"started": True, "message": "Fleet patch discovery started"}
