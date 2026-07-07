import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ScanJob
from ..schemas import HistoryItem

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("", response_model=list[HistoryItem])
def list_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    jobs = (
        db.query(ScanJob)
        .order_by(ScanJob.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        HistoryItem(
            job_id=j.id, url=j.url, domain=j.domain, status=j.status,
            verdict=j.verdict, risk_score=j.risk_score, created_at=j.created_at,
            from_cache=(j.from_cache == "true"),
        )
        for j in jobs
    ]


@router.get("/stats")
def history_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(ScanJob.id)).scalar() or 0

    verdict_rows = (
        db.query(ScanJob.verdict, func.count(ScanJob.id))
        .filter(ScanJob.verdict.isnot(None))
        .group_by(ScanJob.verdict)
        .all()
    )
    verdict_counts = {"safe": 0, "suspicious": 0, "malicious": 0}
    for verdict, count in verdict_rows:
        if verdict in verdict_counts:
            verdict_counts[verdict] = count

    cache_hits = db.query(func.count(ScanJob.id)).filter(ScanJob.from_cache == "true").scalar() or 0
    unique_domains = db.query(func.count(func.distinct(ScanJob.domain))).scalar() or 0

    return {
        "total_scans": total,
        "unique_domains": unique_domains,
        "cache_hits": cache_hits,
        "verdicts": verdict_counts,
    }


@router.get("/export")
def export_history(db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
    return [
        {
            "job_id": j.id,
            "url": j.url,
            "domain": j.domain,
            "status": j.status,
            "verdict": j.verdict,
            "risk_score": j.risk_score,
            "details": json.loads(j.details_json) if j.details_json else None,
            "created_at": j.created_at.isoformat(),
        }
        for j in jobs
    ]


@router.delete("")
def clear_history(db: Session = Depends(get_db)):
    deleted = db.query(ScanJob).delete()
    db.commit()
    return {"deleted": deleted}