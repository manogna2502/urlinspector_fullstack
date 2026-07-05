import json
from datetime import datetime
from urllib.parse import urlparse

from .cache import set_cached_result
from .celery_app import celery_app
from .database import SessionLocal
from .models import ScanJob
from .services.dns_check import resolve_dns
from .services.reputation_check import google_safe_browsing_scan, keyword_and_blacklist_scan
from .services.scoring import compute_score
from .services.ssl_check import check_ssl
from .services.whois_check import check_whois


@celery_app.task(name="app.tasks.inspect_url_task", bind=True, max_retries=1)
def inspect_url_task(self, job_id: str, url: str):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job is None:
            return

        job.status = "running"
        db.commit()

        parsed = urlparse(url)
        domain = parsed.hostname or job.domain
        is_https = parsed.scheme == "https"

        dns_info = resolve_dns(domain)
        whois_info = check_whois(domain)
        ssl_info = check_ssl(domain) if is_https else {
            "has_cert": False, "issuer": None, "valid_from": None,
            "valid_to": None, "days_remaining": None,
            "error": "Skipped: URL is not HTTPS",
        }
        reputation_info = {
            "blacklist": keyword_and_blacklist_scan(url, domain),
            "safe_browsing": google_safe_browsing_scan(url),
        }

        risk_score, verdict = compute_score(dns_info, whois_info, ssl_info, reputation_info)

        details = {
            "dns": dns_info,
            "whois": whois_info,
            "ssl": ssl_info,
            "reputation": reputation_info,
        }

        job.status = "done"
        job.verdict = verdict
        job.risk_score = risk_score
        job.details_json = json.dumps(details)
        job.completed_at = datetime.utcnow()
        db.commit()

        # Cache by domain so repeat lookups (from any user) skip the full pipeline
        set_cached_result(domain, {
            "verdict": verdict,
            "risk_score": risk_score,
            "details": details,
        })

    except Exception as exc:  # noqa: BLE001
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "error"
            job.error_message = str(exc)
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()
