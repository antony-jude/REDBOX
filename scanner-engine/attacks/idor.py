"""
IDOR (Insecure Direct Object Reference) detection module.

Strategy: Request user id 1 (Admin) while sending no auth headers.
In a secure app, this should be blocked. In a vulnerable app, it returns admin user data.
"""
import requests


def test_idor(base_url: str, probe_id: int = 1) -> list[dict]:
    findings = []
    try:
        r = requests.get(f"{base_url}/api/user/{probe_id}", timeout=5)
    except requests.exceptions.RequestException:
        return findings

    # In secure mode, this returns 403/401/error JSON.
    # In vulnerable mode, it returns user data (username/role).
    if r.status_code == 200 and r.text.strip() not in ("", "null") and "username" in r.text:
        findings.append({
            "type": "IDOR",
            "endpoint": f"/api/user/{probe_id}",
            "method": "GET",
            "evidence": r.text[:200],
            "requires_auth": False,
            "produces": ["any_user_data"],
            "requires": ["session_token"],
        })
    return findings
