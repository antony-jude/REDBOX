"""
Path Traversal / Local File Inclusion detection module.

Strategy: Request sensitive configuration/package files using relative
path traversal patterns and inspect if the content is returned unescaped/fully read.
We only use escaping payloads to avoid normal files passing as traversal vulnerabilities.
"""
import requests

def test_path_traversal(base_url: str) -> list[dict]:
    findings = []
    payloads = [
        "../package.json",
        "..\\package.json"
    ]
    for payload in payloads:
        try:
            r = requests.get(f"{base_url}/api/file", params={"name": payload}, timeout=5)
        except requests.exceptions.RequestException:
            continue

        if r.status_code == 200 and "dependencies" in r.text and "vulnerable-app" in r.text:
            findings.append({
                "type": "Path Traversal",
                "endpoint": "/api/file",
                "method": "GET",
                "payload": payload,
                "evidence": r.text[:200],
                "requires_auth": False,
                "produces": ["local_source_code", "env_configuration"],
                "requires": []
            })
            break
    return findings
