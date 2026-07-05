import json
from typing import Any, Optional

import redis

from .config import get_settings

settings = get_settings()
_redis_client: Optional[redis.Redis] = None


def get_redis() -> Optional[redis.Redis]:
    """Lazily connect to Redis. Returns None (cache disabled) if unreachable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        _redis_client = client
        return client
    except Exception:  # noqa: BLE001
        return None


def cache_key_for_domain(domain: str) -> str:
    return f"url-inspector:scan:{domain}"


def get_cached_result(domain: str) -> Optional[dict[str, Any]]:
    client = get_redis()
    if client is None:
        return None
    raw = client.get(cache_key_for_domain(domain))
    return json.loads(raw) if raw else None


def set_cached_result(domain: str, payload: dict[str, Any]) -> None:
    client = get_redis()
    if client is None:
        return
    client.setex(cache_key_for_domain(domain), settings.CACHE_TTL_SECONDS, json.dumps(payload))
