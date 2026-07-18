"""
Generic blackbox attack modules.

The modules in attacks/sqli.py, idor.py, etc. target the bundled
vulnerable-app's exact known routes (/login, /api/user/:id, ...).
These functions instead accept a LIST of discovered or user-supplied
endpoints - {"url", "method", "params"} - and run blackbox heuristics
against each parameter. This is what lets the scanner test ANY app,
not just the one bundled demo target.

HONEST TRADE-OFF: generic blackbox detection is inherently less
precise than testing a known route with a known correct answer.
These heuristics are written to favor fewer false positives over
exhaustive coverage - e.g. SQLi detection looks for actual database
error signatures in the response rather than guessing from status
codes alone.
"""
import requests
import time

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "sqlstate", "sqlite3.operationalerror",
    "unclosed quotation mark", "odbc sql", "pg_query", "postgresql",
    "ora-01756", "you have an error in your sql",
]

SENSITIVE_FILE_MARKERS = ["root:x:0:0:", "[boot loader]", "[fonts]", "# /etc/passwd"]

PATH_PARAM_KEYWORDS = ["file", "path", "name", "doc", "page", "template", "filename"]
URL_PARAM_KEYWORDS = ["url", "uri", "link", "target", "redirect", "callback", "fetch", "src"]
CMD_PARAM_KEYWORDS = ["cmd", "command", "ip", "host", "ping", "exec", "addr"]


def _send(method: str, url: str, data: dict):
    try:
        if method == "GET":
            return requests.get(url, params=data, timeout=6)
        return requests.post(url, data=data, timeout=6)
    except requests.exceptions.RequestException:
        return None


def test_generic_sqli(endpoints: list[dict]) -> list[dict]:
    """Injects a single-quote breaker into each param and looks for a
    real database error signature leaking into the response - the
    most reliable low-false-positive blackbox SQLi signal."""
    findings = []
    for ep in endpoints:
        if not ep["params"]:
            continue
        data = {p: "test" for p in ep["params"]}
        data[ep["params"][0]] = "'"
        r = _send(ep["method"], ep["url"], data)
        if r is None:
            continue
        body_lower = r.text.lower()
        if any(sig in body_lower for sig in SQL_ERROR_SIGNATURES):
            findings.append({
                "type": "SQL Injection",
                "endpoint": ep["url"],
                "method": ep["method"],
                "payload": "'",
                "evidence": r.text[:200],
                "requires_auth": False,
                "produces": ["database_contents"],
                "requires": [],
            })
    return findings


def test_generic_xss(endpoints: list[dict]) -> list[dict]:
    """Injects a unique marker script tag into every param and checks
    if it comes back completely unescaped."""
    findings = []
    marker = "<script>__xssmarker__</script>"
    for ep in endpoints:
        if not ep["params"]:
            continue
        data = {p: marker for p in ep["params"]}
        r = _send(ep["method"], ep["url"], data)
        if r is None:
            continue
        if marker in r.text:
            findings.append({
                "type": "Reflected XSS",
                "endpoint": ep["url"],
                "method": ep["method"],
                "evidence": "Payload reflected unescaped in response",
                "requires_auth": False,
                "produces": ["session_token"],
                "requires": [],
            })
    return findings


def test_generic_path_traversal(endpoints: list[dict]) -> list[dict]:
    """Only tests params whose NAME suggests a file/path purpose - this
    keeps false positives low compared to spraying every param."""
    findings = []
    payload = "../../../../../../etc/passwd"
    for ep in endpoints:
        relevant = [p for p in ep["params"] if any(k in p.lower() for k in PATH_PARAM_KEYWORDS)]
        for param in relevant:
            data = {p: "test" for p in ep["params"]}
            data[param] = payload
            r = _send(ep["method"], ep["url"], data)
            if r is None:
                continue
            if any(marker in r.text for marker in SENSITIVE_FILE_MARKERS):
                findings.append({
                    "type": "Path Traversal",
                    "endpoint": ep["url"],
                    "method": ep["method"],
                    "payload": payload,
                    "evidence": r.text[:200],
                    "requires_auth": False,
                    "produces": ["local_source_code", "env_configuration"],
                    "requires": [],
                })
    return findings


def test_generic_ssrf(endpoints: list[dict]) -> list[dict]:
    """Only tests params whose NAME suggests they accept a URL - points
    them at the AWS/GCP metadata IP, a classic SSRF canary target."""
    findings = []
    for ep in endpoints:
        relevant = [p for p in ep["params"] if any(k in p.lower() for k in URL_PARAM_KEYWORDS)]
        for param in relevant:
            data = {p: "test" for p in ep["params"]}
            data[param] = "http://169.254.169.254/latest/meta-data/"
            r = _send(ep["method"], ep["url"], data)
            if r is None:
                continue
            if r.status_code == 200 and len(r.text.strip()) > 0:
                findings.append({
                    "type": "SSRF",
                    "endpoint": ep["url"],
                    "method": ep["method"],
                    "payload": data[param],
                    "evidence": "Server fetched an attacker-controlled internal URL and returned content",
                    "requires_auth": False,
                    "produces": ["internal_network_access"],
                    "requires": [],
                })
    return findings


def test_generic_command_injection(endpoints: list[dict]) -> list[dict]:
    """Time-based blind detection: inject a `sleep` command separator
    and measure if the response takes meaningfully longer than normal.
    Safe (no destructive commands) and works without needing to see
    command output in the response."""
    findings = []
    for ep in endpoints:
        relevant = [p for p in ep["params"] if any(k in p.lower() for k in CMD_PARAM_KEYWORDS)]
        for param in relevant:
            baseline_data = {p: "test" for p in ep["params"]}
            baseline_start = time.time()
            _send(ep["method"], ep["url"], baseline_data)
            baseline_elapsed = time.time() - baseline_start

            injected_data = {**baseline_data, param: "127.0.0.1; sleep 4"}
            injected_start = time.time()
            r = _send(ep["method"], ep["url"], injected_data)
            injected_elapsed = time.time() - injected_start

            if r is None:
                continue
            # Flag only if the injected request is meaningfully slower
            # than baseline AND crosses an absolute threshold - reduces
            # false positives from naturally slow endpoints.
            if injected_elapsed > 3.5 and injected_elapsed > (baseline_elapsed + 2):
                findings.append({
                    "type": "Command Injection",
                    "endpoint": ep["url"],
                    "method": ep["method"],
                    "payload": injected_data[param],
                    "evidence": f"Baseline {baseline_elapsed:.1f}s vs injected {injected_elapsed:.1f}s - consistent with an executed sleep command",
                    "requires_auth": False,
                    "produces": ["system_shell_access"],
                    "requires": [],
                })
    return findings


def run_all_generic(endpoints: list[dict]) -> list[dict]:
    """Convenience entry point - runs every generic module and returns
    the combined findings list."""
    findings = []
    findings += test_generic_sqli(endpoints)
    findings += test_generic_xss(endpoints)
    findings += test_generic_path_traversal(endpoints)
    findings += test_generic_ssrf(endpoints)
    findings += test_generic_command_injection(endpoints)
    return findings
