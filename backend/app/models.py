import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, String, Text

from .database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=gen_uuid)
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False, index=True)

    # pending -> running -> done | error
    status = Column(String, nullable=False, default="pending")

    verdict = Column(String, nullable=True)       # safe | suspicious | malicious
    risk_score = Column(Float, nullable=True)      # 0-100
    details_json = Column(Text, nullable=True)     # JSON blob: dns, whois, ssl, reputation
    error_message = Column(Text, nullable=True)

    from_cache = Column(String, nullable=False, default="false")  # "true"/"false"

    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
