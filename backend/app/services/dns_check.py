import dns.resolver


def resolve_dns(domain: str) -> dict:
    """Resolve A and MX records for a domain. Never raises; returns error info instead."""
    result = {"a_records": [], "mx_records": [], "resolved": False, "error": None}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [r.to_text() for r in answers]
        result["resolved"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"A record lookup failed: {exc}"

    try:
        mx_answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [r.to_text() for r in mx_answers]
    except Exception:  # noqa: BLE001
        pass  # MX is optional/informational

    return result
