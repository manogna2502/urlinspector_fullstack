import ssl

from slowapi import Limiter
from slowapi.util import get_remote_address

from .config import get_settings

settings = get_settings()

_storage_options = {}
if settings.REDIS_URL.startswith("rediss://"):
    _storage_options["ssl_cert_reqs"] = ssl.CERT_REQUIRED

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    storage_options=_storage_options,
)