"""
Server-Side Request Forgery (SSRF) detection module.

Strategy: Force the server to query internal local servers/ports (e.g. scanner-engine FastAPI health endpoint) 
and verify if the server exposes internal resources.
"""
import requests

def test_ssrf(base_url: str) -> list[dict]:
    findings = []
    # Point server to scanner-engine port 8000 health endpoint
    payload = "http://localhost:8000/api/health"
    try:
        r = requests.get(f"{base_url}/api/fetch-url", params={"url": payload}, timeout=5)
    except requests.exceptions.RequestException:
        return findings

    if r.status_code == 200:
        res_json = r.json()
        content = res_json.get("content", "")
        # If response returned the JSON format of our health API
        if "llm_enabled" in content or "target" in content:
            findings.append({
                "type": "SSRF",
                "endpoint": "/api/fetch-url",
                "method": "GET",
                "payload": payload,
                "evidence": content[:200],
                "requires_auth": False,
                "produces": ["internal_network_access"],
                "requires": []
            })
    return findings
