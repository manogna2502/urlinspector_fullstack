import ssl

from celery import Celery

from .config import get_settings

settings = get_settings()

celery_app = Celery(
    "url_inspector",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks"],
)

_ssl_options = {"ssl_cert_reqs": ssl.CERT_REQUIRED}

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    result_expires=3600,
    # Celery's own SSL config, independent of any query string on the URL —
    # avoids the string-casing pitfalls of embedding ssl_cert_reqs in the URL.
    broker_use_ssl=_ssl_options if settings.CELERY_BROKER_URL.startswith("rediss://") else None,
    redis_backend_use_ssl=_ssl_options if settings.CELERY_RESULT_BACKEND.startswith("rediss://") else None,
)