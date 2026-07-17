"""
CLI runner - a fallback path that doesn't need the FastAPI server or
dashboard running. Useful for quick testing during development.

Run with:  python main.py
Produces:  report.json in this directory
"""
import os
import json
import asyncio
from dotenv import load_dotenv

from attacks import sqli, idor, auth_bypass, xss, path_traversal, command_injection, ssrf
from chain_engine import find_chains, mark_chained_findings
from cvss_scorer import calculate_severity
from llm_analyzer import analyze_finding

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3001")


async def main():
    print(f"Scanning {TARGET_URL} ...")

    findings = []
    findings += sqli.test_sqli(TARGET_URL)
    findings += idor.test_idor(TARGET_URL)
    findings += auth_bypass.test_auth_bypass(TARGET_URL)
    findings += xss.test_xss(TARGET_URL)
    findings += path_traversal.test_path_traversal(TARGET_URL)
    findings += command_injection.test_command_injection(TARGET_URL)
    findings += ssrf.test_ssrf(TARGET_URL)

    print(f"Found {len(findings)} raw findings. Checking for exploit chains...")
    chains = find_chains(findings)
    mark_chained_findings(findings, chains)
    print(f"Found {len(chains)} exploit chain(s).")

    report = []
    for finding in findings:
        cvss = calculate_severity(finding)
        print(f"  Analyzing {finding['type']} ({cvss['severity']})...")
        analysis = await analyze_finding(finding)
        report.append({**finding, "cvss": cvss, "analysis": analysis})

    output = {"target": TARGET_URL, "findings": report, "chains": chains}
    with open("report.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nDone. {len(report)} findings written to report.json")


if __name__ == "__main__":
    asyncio.run(main())
