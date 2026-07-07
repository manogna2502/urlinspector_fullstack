from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, field_validator


class InspectRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


class InspectAccepted(BaseModel):
    job_id: str
    status: str
    from_cache: bool = False


class JobResult(BaseModel):
    job_id: str
    url: str
    domain: str
    status: str
    verdict: Optional[str] = None
    risk_score: Optional[float] = None
    details: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    from_cache: bool = False

    class Config:
        from_attributes = True


class HistoryItem(BaseModel):
    job_id: str
    url: str
    domain: str
    status: str
    verdict: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: datetime
    from_cache: bool = False

    class Config:
        from_attributes = True