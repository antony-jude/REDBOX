"""
RAG (Retrieval-Augmented Generation) grounding layer.

Why this exists: instead of trusting the LLM's memory of "what SQLi is"
(which can drift or hallucinate details), we retrieve a real reference
entry (CWE ID + OWASP-based description) FIRST, then inject that into
the prompt as ground truth the model must base its answer on. This is
the same core pattern production RAG systems use, scoped down to a
small hardcoded knowledge base since we only have ~4-8 vuln categories
to cover in a hackathon.
"""

KNOWLEDGE_BASE = {
    "SQL Injection": {
        "cwe": "CWE-89",
        "reference": (
            "SQL Injection occurs when untrusted input is concatenated directly "
            "into a database query, letting an attacker alter the query's logic "
            "(e.g. bypass a login check). OWASP categorizes this under "
            "A03:2021 - Injection. Standard remediation is parameterized "
            "queries / prepared statements, never string concatenation."
        ),
    },
    "IDOR": {
        "cwe": "CWE-639",
        "reference": (
            "Insecure Direct Object Reference happens when an application "
            "exposes an internal identifier (like a user ID) and does not "
            "verify the requester is authorized to access that specific "
            "object. OWASP categorizes this under A01:2021 - Broken Access "
            "Control. Remediation requires an authorization check comparing "
            "the requested object's owner to the authenticated caller."
        ),
    },
    "Reflected XSS": {
        "cwe": "CWE-79",
        "reference": (
            "Cross-Site Scripting occurs when user-supplied input is written "
            "into an HTML/JS response context without proper output encoding, "
            "allowing attacker-controlled script to execute in the victim's "
            "browser. OWASP A03:2021. Remediation is context-aware output "
            "encoding (e.g. HTML-escaping) on every reflected value."
        ),
    },
    "Broken Access Control": {
        "cwe": "CWE-284",
        "reference": (
            "Missing authorization checks on a sensitive endpoint let any "
            "caller, authenticated or not, reach functionality that should "
            "be restricted. OWASP's #1 ranked category by prevalence in the "
            "2021 Top 10. Remediation requires an explicit role/permission "
            "check before the route handler runs."
        ),
    },
    "Path Traversal": {
        "cwe": "CWE-22",
        "reference": (
            "Path Traversal allows attackers to access arbitrary files on the "
            "filesystem by using directory traversal sequences (like ../). "
            "OWASP A05:2021-Security Misconfiguration. Remediation requires resolving "
            "absolute paths and verifying they start with the intended root directory."
        ),
    },
    "Command Injection": {
        "cwe": "CWE-78",
        "reference": (
            "Command Injection happens when an application passes unsafe user-supplied "
            "data to a system shell, allowing attackers to execute arbitrary shell commands. "
            "OWASP A03:2021-Injection. Remediation requires strict input validation, "
            "using APIs rather than raw shells, or using list/array arguments for subprocesses."
        ),
    },
    "SSRF": {
        "cwe": "CWE-918",
        "reference": (
            "Server-Side Request Forgery occurs when a web application fetches a "
            "remote resource without validating the user-supplied URL. Attackers "
            "use this to scan internal networks, loop back to localhost, or query metadata services. "
            "OWASP A10:2021-Server-Side Request Forgery. Remediation involves DNS pinning, "
            "strict URL whitelisting, or blocking private IP ranges."
        ),
    },
}


def retrieve_context(vuln_type: str) -> dict:
    """Exact-match retrieval. A full vector DB would be overkill for a
    fixed, small set of known vulnerability categories."""
    return KNOWLEDGE_BASE.get(vuln_type, {
        "cwe": "N/A",
        "reference": "No reference entry found for this vulnerability type.",
    })


def build_grounded_prompt(finding: dict, source_context: str = "") -> str:
    context = retrieve_context(finding["type"])
    
    source_prompt_addition = ""
    if source_context:
        source_prompt_addition = f"""
SOURCE CODE CONTEXT:
The following is the extracted source code of the target application. Use this exact source code to generate your `fix_code_diff` patch:
{source_context}
"""

    return f"""You are a security analyst reviewing an automated scan finding.
Use ONLY the reference context below plus the finding evidence to write
your analysis. Do not invent facts beyond what is given.

REFERENCE CONTEXT (CWE: {context['cwe']}):
{context['reference']}
{source_prompt_addition}

FINDING:
Type: {finding['type']}
Endpoint: {finding['endpoint']}
Method: {finding.get('method', 'N/A')}
Evidence: {finding.get('evidence', '')}
Part of an exploit chain: {finding.get('chained', False)}

Respond with ONLY a raw JSON object, no markdown fences, no preamble:
{{
  "cwe_id": "{context['cwe']}",
  "severity": "Critical|High|Medium|Low",
  "explanation": "2-3 sentences grounded in the reference context above, explaining real-world impact",
  "fix": "concrete, specific code-level fix recommendation",
  "fix_code_diff": "a short unified diff showing the exact code change based on the source code provided, or empty string if not applicable"
}}"""
