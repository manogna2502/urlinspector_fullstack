import json

from fastapi import APIRouter, Depends, Query
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
        )
        for j in jobs
    ]


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
