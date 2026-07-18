"""
Simplified CVSS-inspired severity scorer.

Why this exists: letting an LLM freely assign "Critical/High/Medium/Low"
looks arbitrary to a technical judge or reviewer. This module computes
severity from concrete, measurable factors the scanner actually
observed - so every score is explainable and defensible, the same way
real CVSS scoring works (just simplified for a 30-hour build).
"""

# Vuln types that directly expose or let an attacker modify sensitive data.
DIRECT_IMPACT_TYPES = {"SQL Injection", "Broken Access Control"}
LOW_IMPACT_TYPES = {"Missing Security Headers"}


def calculate_severity(finding: dict) -> dict:
    score = 0
    factors = []

    if finding["type"] in LOW_IMPACT_TYPES:
        return {
            "score": 2,
            "severity": "Low",
            "factors": ["A browser hardening control is missing"],
        }

    if finding["type"] in DIRECT_IMPACT_TYPES:
        score += 4
        factors.append("Direct data exposure or modification")

    if not finding.get("requires_auth", False):
        score += 3
        factors.append("Exploitable remotely without any authentication")

    if finding.get("chained", False):
        score += 3
        factors.append("Part of a multi-step exploit chain (see chain_engine)")

    if finding["type"] == "Reflected XSS":
        score += 2
        factors.append("Enables client-side code execution in victim's browser")

    score = min(score, 10)  # cap at 10 to mirror the real CVSS 0-10 scale

    if score >= 8:
        severity = "Critical"
    elif score >= 6:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"

    return {"score": score, "severity": severity, "factors": factors}
