import os
from functools import lru_cache


class Settings:
    """Central place for all environment-driven configuration."""

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./url_inspector.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

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
