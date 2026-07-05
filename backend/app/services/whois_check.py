from datetime import datetime

import whois


def _first(value):
    """python-whois sometimes returns a list of dates instead of a single one."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def check_whois(domain: str) -> dict:
    """Look up domain registration/age info. Never raises; returns error info instead."""
    result = {
        "registrar": None,
        "created": None,
        "expires": None,
        "age_days": None,
        "error": None,
    }

    try:
        record = whois.whois(domain)
        created = _first(record.creation_date)
        expires = _first(record.expiration_date)

        result["registrar"] = record.registrar
        result["created"] = created.isoformat() if isinstance(created, datetime) else created
        result["expires"] = expires.isoformat() if isinstance(expires, datetime) else expires

        if isinstance(created, datetime):
            age_days = (datetime.utcnow() - created).days
            result["age_days"] = age_days
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"WHOIS lookup failed: {exc}"

    return result
