"""OWASP Top 10:2025 coverage inventory for an honest hybrid assessment."""

OWASP_TOP_10_2025 = [
    ("A01:2025", "Broken Access Control", "Automated", "IDOR, admin-route, and SSRF checks; verify roles and tenant boundaries with authenticated test accounts."),
    ("A02:2025", "Security Misconfiguration", "Automated", "Security headers, unsafe CORS, and exposed error detail checks."),
    ("A03:2025", "Software Supply Chain Failures", "Human review", "Review dependency manifests, lockfiles, build provenance, and CI/CD permissions."),
    ("A04:2025", "Cryptographic Failures", "Human review", "Review TLS, key storage, encryption use, password hashing, and data classification."),
    ("A05:2025", "Injection", "Automated", "SQL injection, reflected XSS, path traversal, command injection, and SSRF checks."),
    ("A06:2025", "Insecure Design", "Human review", "Threat-model critical workflows, rate limits, abuse cases, and business rules with product owners."),
    ("A07:2025", "Authentication Failures", "Source-assisted", "Test session lifecycle, password reset, MFA, and brute-force controls with authorized test accounts."),
    ("A08:2025", "Software or Data Integrity Failures", "Source-assisted", "Review signed updates, deserialization, webhook verification, and CI/CD artifact integrity."),
    ("A09:2025", "Security Logging and Alerting Failures", "Human review", "Confirm security events are logged, retained, monitored, and trigger actionable alerts."),
    ("A10:2025", "Mishandling of Exceptional Conditions", "Automated", "Check normal responses for exposed stack traces and validate error handling manually."),
]


FINDING_CATEGORY = {
    "IDOR": "A01:2025",
    "Broken Access Control": "A01:2025",
    "SSRF": "A01:2025",
    "Missing Security Headers": "A02:2025",
    "Unsafe CORS Policy": "A02:2025",
    "SQL Injection": "A05:2025",
    "Reflected XSS": "A05:2025",
    "Path Traversal": "A05:2025",
    "Command Injection": "A05:2025",
    "Sensitive Error Details Exposed": "A10:2025",
}


def build_coverage(findings: list[dict]) -> list[dict]:
    found_categories = {FINDING_CATEGORY.get(item.get("type")) for item in findings}
    return [
        {
            "id": category_id,
            "name": name,
            "coverage": coverage,
            "status": "Finding detected" if category_id in found_categories else "No finding from this scan",
            "next_step": next_step,
        }
        for category_id, name, coverage, next_step in OWASP_TOP_10_2025
    ]
