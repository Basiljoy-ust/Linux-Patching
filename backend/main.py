"""Linux Patching API — application entry point.

The endpoints live in routers/ and the shared Ansible/DB helpers in core/.
Split out of this file on refactor/split-backend with no behaviour change.
"""

from time import perf_counter

from fastapi import FastAPI, Request

from core.config import api_logger
from routers import assets as assets_router
from routers import patching as patching_router


app = FastAPI(
    title="Linux Patching API",
    version="1.0.0",
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
