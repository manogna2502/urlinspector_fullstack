import socket
import ssl
from datetime import datetime


def check_ssl(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Fetch and summarize the TLS certificate presented by a host. Never raises."""
    result = {
        "has_cert": False,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "error": None,
    }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        result["has_cert"] = True
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        result["valid_from"] = not_before
        result["valid_to"] = not_after

        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result["days_remaining"] = (expiry - datetime.utcnow()).days

    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSL check failed: {exc}"

    return result
