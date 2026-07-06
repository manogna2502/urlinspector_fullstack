import os
from functools import lru_cache
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def _set_ssl_cert_reqs(url: str, value: str) -> str:
    """
    rediss:// (TLS) URLs need an explicit ssl_cert_reqs param, but different
    libraries expect different casing for the same value:
      - the `limits` library (used by slowapi's rate limiter) wants lowercase,
        e.g. "required"
      - Celery's redis backend explicitly requires the uppercase form,
        e.g. "CERT_REQUIRED"
    So we can't share one URL for both — force the value each consumer needs,
    overwriting any existing ssl_cert_reqs param rather than only filling it
    in when missing (this also protects against a stale/wrong value having
    been pasted into an env var by hand).
    """
    if not url or not url.startswith("rediss://"):
        return url

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["ssl_cert_reqs"] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class Settings:
    """Central place for all environment-driven configuration."""

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./url_inspector.db")

    _raw_redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0").strip()
    _raw_broker_url = os.getenv("CELERY_BROKER_URL", "").strip() or _raw_redis_url
    _raw_backend_url = os.getenv("CELERY_RESULT_BACKEND", "").strip() or _raw_redis_url

    # Used by cache.py and the rate limiter (via the `limits` library)
    REDIS_URL: str = _set_ssl_cert_reqs(_raw_redis_url, "required")

    # Used by Celery, which requires the uppercase CERT_ form
    CELERY_BROKER_URL: str = _set_ssl_cert_reqs(_raw_broker_url, "CERT_REQUIRED")
    CELERY_RESULT_BACKEND: str = _set_ssl_cert_reqs(_raw_backend_url, "CERT_REQUIRED")

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