"""Linux Patching API — application entry point.

The endpoints live in routers/ and the shared Ansible/DB helpers in core/.
Zero-Day Radar intel is synced in the background (zeroday/sync.py) and
served by the /api/zeroday and /api/dashboard endpoints.
"""

import os
from contextlib import asynccontextmanager
from time import perf_counter

from fastapi import FastAPI, Request

from core.config import api_logger
from routers import asset_vulns as asset_vulns_router
from routers import assets as assets_router
from routers import dashboard as dashboard_router
from routers import patch_jobs as patch_jobs_router
from routers import patching as patching_router
from routers import updates as updates_router
from routers import zeroday as zeroday_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Zero-Day Radar background sync; disable with ZERODAY_SYNC_ENABLED=0
    # (e.g. in tests, or on a box without a radar instance).
    if os.environ.get("ZERODAY_SYNC_ENABLED", "1") != "0":
        from zeroday.sync import start_background

        start_background()
    yield


app = FastAPI(
    title="Linux Patching API",
    version="1.1.0",
    lifespan=lifespan,
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


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


app.include_router(assets_router.router)
app.include_router(patching_router.router)
app.include_router(dashboard_router.router)
app.include_router(updates_router.router)
app.include_router(patch_jobs_router.router)
app.include_router(zeroday_router.router)
app.include_router(asset_vulns_router.router)
