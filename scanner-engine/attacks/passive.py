"""Low-impact web security checks for applications the operator is authorized to test."""
import requests


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

STACK_TRACE_MARKERS = (
    "traceback (most recent call last)", "stack trace", "at process.",
    "exception in thread", "sqlstate", "syntaxerror:",
)


def test_security_headers(target_url: str) -> list[dict]:
    """Checks response headers only; it does not submit payloads or alter state."""
    try:
        response = requests.get(target_url, timeout=6, allow_redirects=True)
    except requests.exceptions.RequestException:
        return []

    missing = [label for key, label in SECURITY_HEADERS.items() if key not in response.headers]
    if response.url.startswith("https://") and "strict-transport-security" not in response.headers:
        missing.append("Strict-Transport-Security")
    if not missing:
        return []
    return [{
        "type": "Missing Security Headers",
        "endpoint": response.url,
        "method": "GET",
        "evidence": "Missing response headers: " + ", ".join(missing),
        "requires_auth": False,
        "produces": [],
        "requires": [],
    }]


def test_permissive_cors(target_url: str) -> list[dict]:
    """Makes one read-only request with an untrusted Origin header."""
    try:
        response = requests.get(
            target_url,
            headers={"Origin": "https://untrusted.example"},
            timeout=6,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException:
        return []

    origin = response.headers.get("access-control-allow-origin", "")
    credentials = response.headers.get("access-control-allow-credentials", "").lower()
    if origin == "https://untrusted.example" and credentials == "true":
        evidence = "Server reflected an untrusted Origin while allowing credentials."
    elif origin == "*" and credentials == "true":
        evidence = "Server allows every Origin and also allows credentials."
    else:
        return []
    return [{
        "type": "Unsafe CORS Policy",
        "endpoint": response.url,
        "method": "GET",
        "evidence": evidence,
        "requires_auth": False,
        "produces": ["cross_origin_data_access"],
        "requires": [],
    }]


def test_information_disclosure(target_url: str) -> list[dict]:
    """Looks for error details already exposed by a normal GET response."""
    try:
        response = requests.get(target_url, timeout=6, allow_redirects=True)
    except requests.exceptions.RequestException:
        return []

    body = response.text.lower()
    marker = next((item for item in STACK_TRACE_MARKERS if item in body), None)
    if not marker:
        return []
    return [{
        "type": "Sensitive Error Details Exposed",
        "endpoint": response.url,
        "method": "GET",
        "evidence": f"Response exposes error detail matching: {marker}",
        "requires_auth": False,
        "produces": ["implementation_details"],
        "requires": [],
    }]
