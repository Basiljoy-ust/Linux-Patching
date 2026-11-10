"""A2 — GET /api/dashboard/summary: the Overview tiles and donut."""

from fastapi import APIRouter

from services import fleet_join

router = APIRouter()


@router.get("/api/dashboard/summary")
def dashboard_summary():
    return fleet_join.dashboard_summary()
