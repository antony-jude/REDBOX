"""
Reflected XSS detection module.

Strategy: send a harmless-but-detectable <script> payload as a query
param and check if it comes back in the HTML response completely
unescaped. Unescaped == the browser would execute it.

"produces": ["session_token"] models the real-world consequence: a
working XSS payload could be swapped for one that steals the victim's
session cookie, which chain_engine.py links forward into the IDOR bug.
"""
import requests

XSS_PAYLOAD = "<script>alert(1)</script>"


def test_xss(base_url: str) -> list[dict]:
    findings = []
    try:
        r = requests.get(f"{base_url}/comment", params={"text": XSS_PAYLOAD}, timeout=5)
    except requests.exceptions.RequestException:
        return findings

    if XSS_PAYLOAD in r.text:
        findings.append({
            "type": "Reflected XSS",
            "endpoint": "/comment",
            "method": "GET",
            "evidence": "Payload reflected unescaped in HTML response",
            "requires_auth": False,
            "produces": ["session_token"],
            "requires": [],
        })
    return findings
