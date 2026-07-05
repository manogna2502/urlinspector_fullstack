import json
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..cache import get_cached_result
from ..database import get_db
from ..models import ScanJob
from ..rate_limit import limiter
from ..schemas import InspectAccepted, InspectRequest, JobResult
from ..tasks import inspect_url_task
from ..config import get_settings

router = APIRouter(prefix="/api", tags=["inspect"])
settings = get_settings()


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if "://" not in raw_url:
        raw_url = f"https://{raw_url}"
    return raw_url


@router.post("/inspect", response_model=InspectAccepted, status_code=202)
@limiter.limit(settings.RATE_LIMIT_INSPECT)
def submit_url(request: Request, payload: InspectRequest, db: Session = Depends(get_db)):
    url = normalize_url(payload.url)
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain:
        raise HTTPException(status_code=400, detail="Could not parse a valid domain from that URL.")

    # Serve instantly from cache if we've scanned this domain recently
    cached = get_cached_result(domain)
    if cached:
        job = ScanJob(
            url=url,
            domain=domain,
            status="done",
            verdict=cached["verdict"],
            risk_score=cached["risk_score"],
            details_json=json.dumps(cached["details"]),
            from_cache="true",
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return InspectAccepted(job_id=job.id, status="done", from_cache=True)

    job = ScanJob(url=url, domain=domain, status="pending")
    db.add(job)
    db.commit()
    db.refresh(job)

    inspect_url_task.delay(job.id, url)

    return InspectAccepted(job_id=job.id, status="pending", from_cache=False)


@router.get("/jobs/{job_id}", response_model=JobResult)
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobResult(
        job_id=job.id,
        url=job.url,
        domain=job.domain,
        status=job.status,
        verdict=job.verdict,
        risk_score=job.risk_score,
        details=json.loads(job.details_json) if job.details_json else None,
        error_message=job.error_message,
        created_at=job.created_at,
        completed_at=job.completed_at,
        from_cache=(job.from_cache == "true"),
    )
