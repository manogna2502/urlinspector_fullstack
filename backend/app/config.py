import os
from functools import lru_cache
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def _normalize_redis_url(url: str) -> str:
    """
    rediss:// (TLS) URLs require an explicit ssl_cert_reqs param for both
    redis-py and Celery, which Upstash's connection string doesn't include.
    Add it automatically so it doesn't have to be pasted in by hand.
    """
    if not url or not url.startswith("rediss://"):
        return url

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if "ssl_cert_reqs" not in query:
        query["ssl_cert_reqs"] = ["CERT_REQUIRED"]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class Settings:
    """Central place for all environment-driven configuration."""

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./url_inspector.db")
    REDIS_URL: str = _normalize_redis_url(os.getenv("REDIS_URL", "redis://localhost:6379/0").strip())

    CELERY_BROKER_URL: str = _normalize_redis_url(os.getenv("CELERY_BROKER_URL", "").strip()) or REDIS_URL
    CELERY_RESULT_BACKEND: str = _normalize_redis_url(os.getenv("CELERY_RESULT_BACKEND", "").strip()) or REDIS_URL

    # Optional: set this to enable real Google Safe Browsing lookups.
    # Without it, the app falls back to heuristic + blacklist scoring only.
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "3600"))

    RATE_LIMIT_INSPECT: str = os.getenv("RATE_LIMIT_INSPECT", "5/minute")

    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # Optional absolute override; if unset, main.py falls back to ../../frontend
    FRONTEND_DIR: str = os.getenv("FRONTEND_DIR", "")


@lru_cache
def get_settings() -> Settings:
    return Settings()