import httpx

from ..config import get_settings

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "bank", "reset", "confirm",
    "update", "account", "signin", "wallet", "free", "gift", "win",
]

BLACKLISTED_DOMAINS = {"phishy.com", "malicious-site.net", "badlink.org"}

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk", "click"}


def keyword_and_blacklist_scan(url: str, domain: str) -> dict:
    lower_url = url.lower()
    matched_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lower_url]
    is_blacklisted = domain in BLACKLISTED_DOMAINS
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    suspicious_tld = tld in SUSPICIOUS_TLDS

    return {
        "matched_keywords": matched_keywords,
        "is_blacklisted": is_blacklisted,
        "suspicious_tld": suspicious_tld,
    }


def google_safe_browsing_scan(url: str) -> dict:
    """Calls Google Safe Browsing v4 if an API key is configured. Otherwise skipped."""
    settings = get_settings()
    result = {"checked": False, "threats_found": [], "error": None}

    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return result

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {"clientId": "url-inspector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
        result["checked"] = True
        result["threats_found"] = [m.get("threatType") for m in data.get("matches", [])]
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Safe Browsing check failed: {exc}"

    return result
