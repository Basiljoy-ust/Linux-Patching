"""A6/A7/A8 — multi-server patch jobs and history.

POST /api/patch-jobs        -> start a job across one or more servers
GET  /api/patch-jobs/{id}   -> progress / results of a group or single job
GET  /api/patch-jobs        -> history list (groups + legacy single jobs)
"""

from fastapi import APIRouter, HTTPException, Query

from schemas.jobs import PatchJobGroupCreate
from services import job_runner

router = APIRouter()


@router.post("/api/patch-jobs", status_code=202)
def create_patch_job_group(request: PatchJobGroupCreate):
    targets = [
        {"asset_id": target.asset_id, "packages": target.packages}
        for target in request.targets
    ]

    seen = set()
    for target in targets:
        if target["asset_id"] in seen:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate asset in targets: {target['asset_id']}",
            )
        seen.add(target["asset_id"])

    outcome = job_runner.create_group(targets)

    if "error" in outcome:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Some assets cannot be patched",
                **outcome["error"],
            },
        )

    return outcome


@router.get("/api/patch-jobs/{job_id}")
def get_patch_job(job_id: str):
    job = job_runner.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Patch job not found")
    return job


@router.get("/api/patch-jobs")
def list_patch_jobs(limit: int = Query(50, ge=1, le=200)):
    return job_runner.list_jobs(limit=limit)
