def compute_score(dns_info: dict, whois_info: dict, ssl_info: dict, reputation_info: dict) -> tuple[float, str]:
    """
    Combine signals into a 0-100 risk score and a verdict.
    Higher score = higher risk. This is a transparent heuristic, not a black box.
    """
    score = 0.0

    # --- Reputation signals (heaviest weight) ---
    if reputation_info["blacklist"]["is_blacklisted"]:
        score += 60
    if reputation_info["blacklist"]["matched_keywords"]:
        score += min(len(reputation_info["blacklist"]["matched_keywords"]) * 6, 18)
    if reputation_info["blacklist"]["suspicious_tld"]:
        score += 10

    gsb = reputation_info.get("safe_browsing", {})
    if gsb.get("threats_found"):
        score += 70  # a confirmed Google Safe Browsing hit dominates the score

    # --- DNS signal ---
    if not dns_info.get("resolved"):
        score += 15  # doesn't even resolve - treat as risky/unreachable

    # --- WHOIS / domain age signal ---
    age_days = whois_info.get("age_days")
    if age_days is not None:
        if age_days < 30:
            score += 20
        elif age_days < 180:
            score += 10
    elif whois_info.get("error"):
        score += 5  # unknown age is a mild negative signal

    # --- SSL signal ---
    if not ssl_info.get("has_cert"):
        score += 15
    else:
        days_remaining = ssl_info.get("days_remaining")
        if days_remaining is not None and days_remaining < 0:
            score += 15  # expired cert

    score = max(0.0, min(100.0, score))

    if score >= 60:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return round(score, 1), verdict
