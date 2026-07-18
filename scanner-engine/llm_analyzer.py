"""
LLM analysis layer.

Takes a finding, builds a RAG-grounded prompt (rag_grounding.py), and
asks Claude to prioritize/explain/suggest a fix. Runs the blocking SDK
call in a thread via asyncio.to_thread so it doesn't stall the FastAPI
event loop while waiting on the API.

FALLBACK ANALYSIS DESIGN: if ANTHROPIC_API_KEY is missing, this module
generates high-fidelity offline descriptions and code diffs for all 7 vulnerability types.
"""
import os
import json
import asyncio
from pathlib import Path

from rag_grounding import build_grounded_prompt

USE_LLM = bool(os.getenv("GEMINI_API_KEY"))

if USE_LLM:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def _call_gemini_sync(prompt: str) -> str:
    """Blocking SDK call - wrapped with asyncio.to_thread by the caller."""
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1
        )
    )
    return response.text


SOURCE_EXTENSIONS = {".js", ".ts", ".tsx", ".py", ".java", ".go", ".rb", ".php", ".cs"}
SOURCE_CONTEXT_LIMIT = 120_000


def _source_context(source_dir: str) -> str:
    """Read a bounded, source-only context. Uploaded source is never modified."""
    chunks = []
    remaining = SOURCE_CONTEXT_LIMIT
    for path in Path(source_dir).rglob("*"):
        if remaining <= 0:
            break
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if any(part.startswith(".") or part in {"node_modules", "vendor", "dist", "build"} for part in path.parts):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:remaining]
        except OSError:
            continue
        if content:
            chunks.append(f"--- {path.relative_to(source_dir)} ---\n{content}\n")
            remaining -= len(content)
    return "\n".join(chunks)


def _source_reference(finding: dict, source_context: str) -> str:
    """Find a review location when the optional LLM is unavailable."""
    if not source_context:
        return ""
    endpoint = str(finding.get("endpoint", "")).strip("/").split("/")[-1]
    keywords = {
        "SQL Injection": ("select ", "query", "execute", "cursor"),
        "Reflected XSS": ("res.send", "innerhtml", "render", "response.write"),
        "Path Traversal": ("sendfile", "open(", "readfile", "path.join"),
        "Command Injection": ("exec(", "spawn", "subprocess", "system("),
        "SSRF": ("fetch(", "requests.", "http.get", "axios"),
        "IDOR": ("params", "find", "get(", "user_id"),
        "Broken Access Control": ("admin", "auth", "authorize", "role"),
    }.get(finding.get("type"), ())
    current_file = ""
    for line_number, line in enumerate(source_context.splitlines(), start=1):
        if line.startswith("--- "):
            current_file = line[4:].rstrip(" -")
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords) or (endpoint and endpoint in lowered):
            return f"Review candidate: {current_file}:{line_number}. Verify it handles {finding.get('type')} safely before changing it."
    return "Source was reviewed, but no reliable matching line was found; use the suggested control at the affected endpoint."


def _fallback_analysis(finding: dict, source_context: str = "") -> dict:
    t = finding.get("type", "")
    
    analysis_database = {
        "SQL Injection": {
            "cwe_id": "CWE-89",
            "severity": "Critical",
            "explanation": "Username/password parameters are directly concatenated into the SQL statement, allowing attackers to bypass authentication entirely by injecting boolean logic payload strings.",
            "fix": "Use parameterized queries or prepared statement bindings instead of string template interpolation.",
            "fix_code_diff": (
                "@@ -36,8 +36,8 @@\n"
                " app.post('/login', (req, res) => {\n"
                "   const { username, password } = req.body || {};\n"
                "-  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;\n"
                "-  db.get(query, (err, row) => {\n"
                "+  db.get(`SELECT * FROM users WHERE username=? AND password=?`, [username, password], (err, row) => {\n"
                "     if (err) return res.status(500).json({ success: false, error: err.message });"
            )
        },
        "IDOR": {
            "cwe_id": "CWE-639",
            "severity": "High",
            "explanation": "No validation is conducted to verify if the requester has permission to read the requested user ID object, which allows arbitrary user data extraction.",
            "fix": "Implement authorization check comparing the requested resource owner identifier to the authenticated requester identifier.",
            "fix_code_diff": (
                "@@ -51,4 +51,9 @@\n"
                " app.get('/api/user/:id', (req, res) => {\n"
                "   const id = parseInt(req.params.id, 10);\n"
                "+  const mockCurrentUserRole = req.headers['x-user-role'] || 'user';\n"
                "+  const mockCurrentUserId = parseInt(req.headers['x-user-id'] || '2', 10);\n"
                "+  if (mockCurrentUserRole !== 'admin' && mockCurrentUserId !== id) {\n"
                "+    return res.status(403).json({ error: 'Access denied: unauthorized object access' });\n"
                "+  }\n"
                "   db.get(`SELECT id, username, role FROM users WHERE id=?`, [id], (err, row) => {"
            )
        },
        "Broken Access Control": {
            "cwe_id": "CWE-284",
            "severity": "High",
            "explanation": "The admin panel users endpoint fails to enforce authorization checks. Any unauthenticated caller can download the list of all registered users.",
            "fix": "Add an authentication header and token validation check before handling database records request.",
            "fix_code_diff": (
                "@@ -63,4 +63,9 @@\n"
                " app.get('/admin/users', (req, res) => {\n"
                "+  const authHeader = req.headers['authorization'];\n"
                "+  if (!authHeader || authHeader !== 'Bearer admin-token-1337') {\n"
                "+    return res.status(401).json({ error: 'Unauthorized: Admin privileges required' });\n"
                "+  }\n"
                "   db.all(`SELECT id, username, role FROM users`, (err, rows) => {"
            )
        },
        "Reflected XSS": {
            "cwe_id": "CWE-79",
            "severity": "Medium",
            "explanation": "User-supplied query parameters are printed directly to the HTML response document context without HTML entity encoding, which allows external scripts to execute in user browsers.",
            "fix": "Perform context-aware HTML entity escaping on dynamic parameters printed in responses.",
            "fix_code_diff": (
                "@@ -75,4 +75,11 @@\n"
                " app.get('/comment', (req, res) => {\n"
                "   const text = req.query.text || '';\n"
                "-  res.send(`<html><body><h3>You said: ${text}</h3></body></html>`);\n"
                "+  const escaped = text\n"
                "+    .replace(/&/g, '&amp;')\n"
                "+    .replace(/</g, '&lt;')\n"
                "+    .replace(/>/g, '&gt;')\n"
                "+    .replace(/\"/g, '&quot;')\n"
                "+    .replace(/'/g, '&#x27;');\n"
                "+  res.send(`<html><body><h3>You said: ${escaped}</h3></body></html>`);\n"
                " });"
            )
        },
        "Path Traversal": {
            "cwe_id": "CWE-22",
            "severity": "High",
            "explanation": "Input parameters are combined with directory paths directly. An attacker can use traversal syntax like '../' to read files outside the intended file storage root directory.",
            "fix": "Resolve absolute paths and verify they start with the designated base directory path before reading files.",
            "fix_code_diff": (
                "@@ -150,4 +150,8 @@\n"
                " app.get('/api/file', (req, res) => {\n"
                "   const filename = req.query.name || '';\n"
                "   const baseDir = path.resolve(__dirname);\n"
                "   const targetPath = path.resolve(baseDir, filename);\n"
                "+  if (!targetPath.startsWith(baseDir)) {\n"
                "+    return res.status(403).json({ error: 'Forbidden: Path traversal attempt detected' });\n"
                "+  }\n"
                "   res.sendFile(targetPath, (err) => {"
            )
        },
        "Command Injection": {
            "cwe_id": "CWE-78",
            "severity": "Critical",
            "explanation": "The endpoint accepts query arguments and passes them directly to a system shell execution script. Attackers can execute arbitrary command shells on the host OS.",
            "fix": "Validate inputs with a strict whitelist regex pattern or avoid passing shell characters entirely.",
            "fix_code_diff": (
                "@@ -170,4 +170,8 @@\n"
                " app.post('/api/ping', (req, res) => {\n"
                "   const ip = req.body.ip || '';\n"
                "+  const ipv4Regex = /^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/;\n"
                "+  if (!ipv4Regex.test(ip.trim())) {\n"
                "+    return res.status(400).json({ error: 'Invalid IP address' });\n"
                "+  }\n"
                "   const pingCommand = process.platform === 'win32' ? `ping -n 1 ${ip}` : `ping -c 1 ${ip}`;"
            )
        },
        "SSRF": {
            "cwe_id": "CWE-918",
            "severity": "High",
            "explanation": "The backend fetches remote URL requests directly. Attackers can leverage this to scan internal network devices, call loopback interfaces, or query private metadata services.",
            "fix": "Parse targets and compare hostname against a blacklist of local IPs and localhost domains.",
            "fix_code_diff": (
                "@@ -190,4 +190,11 @@\n"
                " app.get('/api/fetch-url', (req, res) => {\n"
                "   const targetUrl = req.query.url || '';\n"
                "+  try {\n"
                "+    const parsedUrl = new URL(targetUrl);\n"
                "+    const hostname = parsedUrl.hostname.toLowerCase();\n"
                "+    if (hostname === 'localhost' || hostname === '127.0.0.1') {\n"
                "+      return res.status(403).json({ error: 'Forbidden' });\n"
                "+    }\n"
                "+  } catch (e) { return res.status(400).json({ error: 'Invalid URL' }); }\n"
                "   http.get(targetUrl, (response) => {"
            )
        },
        "Missing Security Headers": {
            "cwe_id": "CWE-693",
            "severity": "Low",
            "explanation": "The application response is missing browser security headers. This does not prove an exploit by itself, but it removes safeguards that limit the impact of common browser-based attacks.",
            "fix": "Set Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or SAMEORIGIN), and a strict Referrer-Policy on every response.",
            "fix_code_diff": ""
        },
        "Unsafe CORS Policy": {
            "cwe_id": "CWE-942",
            "severity": "High",
            "explanation": "The server accepted an untrusted website as an allowed origin while permitting credentials. A malicious website could potentially read authenticated responses in a victim's browser.",
            "fix": "Replace wildcard or reflected origins with an explicit allowlist of your frontend origins. Do not enable credentialed CORS unless the endpoint requires it.",
            "fix_code_diff": ""
        },
        "Sensitive Error Details Exposed": {
            "cwe_id": "CWE-209",
            "severity": "Medium",
            "explanation": "The response reveals a stack trace or internal error detail. That information can help an attacker understand the application and target later attacks.",
            "fix": "Log the detailed exception on the server, but return a generic error message such as 'An unexpected error occurred' to the client.",
            "fix_code_diff": ""
        }
    }
    
    result = analysis_database.get(t, {
        "cwe_id": "N/A",
        "severity": "Medium",
        "explanation": f"[Offline Analysis] {t} detected at {finding.get('endpoint', 'endpoint')}.",
        "fix": "Perform standard sanitization and verification of inputs.",
        "fix_code_diff": ""
    }).copy()
    source_reference = _source_reference(finding, source_context)
    if source_reference:
        result["source_reference"] = source_reference
        # A demo diff cannot safely be presented as a patch for an unknown upload.
        result["fix_code_diff"] = ""
    return result


async def analyze_finding(finding: dict, source_dir: str = None) -> dict:
    source_context = _source_context(source_dir) if source_dir and os.path.exists(source_dir) else ""
    if not USE_LLM:
        return _fallback_analysis(finding, source_context)

    prompt = build_grounded_prompt(finding, source_context)
    try:
        raw_text = await asyncio.to_thread(_call_gemini_sync, prompt)
        cleaned = raw_text.strip().replace("```json", "").replace("```", "").strip()
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return _fallback_analysis(finding, source_context)
    except Exception:
        return _fallback_analysis(finding, source_context)


async def summarize_assessment(findings: list[dict], coverage: list[dict]) -> dict:
    """Second LLM role: produce a short, management-ready assessment summary."""
    highest = max((item.get("cvss", {}).get("score", 0) for item in findings), default=0)
    fallback = {
        "risk_level": "Critical" if highest >= 8 else "High" if highest >= 6 else "Medium" if findings else "Low",
        "summary": (
            f"The scan found {len(findings)} issue(s). Address the highest-severity findings first, then retest the affected routes. "
            "This automated scan is not a complete security assessment; complete the human-review items in the OWASP coverage matrix."
        ),
        "priority_actions": [item.get("analysis", {}).get("fix", "Review the finding.") for item in findings[:3]],
        "human_review": [item["name"] for item in coverage if item["coverage"] != "Automated"],
    }
    if not USE_LLM:
        return fallback

    compact_findings = [
        {"type": item.get("type"), "severity": item.get("cvss", {}).get("severity"), "endpoint": item.get("endpoint")}
        for item in findings
    ]
    prompt = f"""You are an application-security lead. Summarize this authorized OWASP assessment using only the supplied data. Do not claim the application is secure or that a finding is exploitable beyond the evidence. Use plain language.

FINDINGS: {json.dumps(compact_findings)}
HUMAN REVIEW CATEGORIES: {json.dumps(fallback['human_review'])}

Return raw JSON only:
{{"risk_level":"Critical|High|Medium|Low","summary":"two concise sentences","priority_actions":["action 1","action 2","action 3"],"human_review":["category"]}}"""
    try:
        raw_text = await asyncio.to_thread(_call_gemini_sync, prompt)
        result = json.loads(raw_text.strip().replace("```json", "").replace("```", "").strip())
        if isinstance(result.get("priority_actions"), list):
            return result
    except Exception:
        pass
    return fallback
