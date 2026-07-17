"""
Broken Access Control detection module.

Strategy: hit a route that should require admin privileges while sending
ZERO auth headers/cookies. If it returns 200 with data, there's no
access control on that route at all.

"requires": ["admin_credentials"] links this to the SQLi finding in
chain_engine.py: SQLi steals admin creds -> those creds would grant full
legitimate admin access -> combined severity is far worse than either
bug alone.
"""
import requests


def test_auth_bypass(base_url: str) -> list[dict]:
    findings = []
    try:
        r = requests.get(f"{base_url}/admin/users", timeout=5)
    except requests.exceptions.RequestException:
        return findings

    if r.status_code == 200:
        findings.append({
            "type": "Broken Access Control",
            "endpoint": "/admin/users",
            "method": "GET",
            "evidence": "Admin endpoint returned data with zero auth headers sent",
            "requires_auth": False,
            "produces": ["admin_panel_access"],
            "requires": ["admin_credentials"],
        })
    return findings
