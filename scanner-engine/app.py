"""
Main orchestrator - FastAPI server for AI Red-Team-in-a-Box.

Flow on POST /api/scan:
  1. Resolve source code context: uploaded ZIP, or a GitHub link cloned
     server-side. Either way this is ONLY used to generate suggested
     fix_code_diff patches - nothing is ever written back to disk or
     applied automatically. Suggestion only, never auto-modification.
  2. Run the known demo-specific modules (SQLi, IDOR, Auth Bypass, XSS,
     Path Traversal, Command Injection, SSRF) against target_url - these
     are safe no-ops against any app that doesn't have those exact routes.
  3. Crawl target_url + merge in any user-supplied custom_endpoints, then
     run the generic blackbox modules against that combined endpoint list
     - this is what lets the scanner test ANY app, not just the bundled demo.
  4. Detect multi-hop exploit chains and score everything.
  5. Stream step-by-step logs + findings to the client over WebSockets.
"""
import os
import json
import asyncio
import tempfile
import shutil
import zipfile
import subprocess
import sys
import requests
from pathlib import Path
from urllib.parse import urlparse

# Ensure local directories are in the Python search path (critical for Vercel/lambda environments)
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from attacks import sqli, idor, auth_bypass, xss, path_traversal, command_injection, ssrf
from attacks import generic, passive
import recon
from chain_engine import find_chains, mark_chained_findings
from cvss_scorer import calculate_severity
from llm_analyzer import analyze_finding
from llm_analyzer import summarize_assessment
from owasp_assessment import build_coverage
from source_scanner import scan as scan_source

load_dotenv()

TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3001")

app = FastAPI(title="AI Red-Team-in-a-Box")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients: list[WebSocket] = []

MAX_SOURCE_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_SOURCE_FILES = 2_000
MAX_SOURCE_UNCOMPRESSED_BYTES = 100 * 1024 * 1024


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


async def broadcast(payload: dict):
    dead_clients = []
    for client in connected_clients:
        try:
            await client.send_json(payload)
        except Exception:
            dead_clients.append(client)
    for dead in dead_clients:
        connected_clients.remove(dead)


async def log_to_terminal(msg: str, status: str = "info"):
    await broadcast({"event": "log", "data": {"message": msg, "status": status}})
    await asyncio.sleep(0.15)


@app.get("/api/health")
async def health():
    return {"status": "ok", "target": TARGET_URL, "llm_enabled": bool(os.getenv("GEMINI_API_KEY"))}


def _resolve_source_from_zip(source_code: UploadFile) -> tuple[str | None, object | None]:
    """Extracts an uploaded ZIP into a temp dir. Returns (source_dir, temp_dir_obj)
    so the caller can clean up afterwards. Never writes back to the ZIP itself."""
    temp_dir_obj = tempfile.TemporaryDirectory()
    source_dir = temp_dir_obj.name
    zip_path = os.path.join(source_dir, "upload.zip")
    bytes_written = 0
    with open(zip_path, "wb") as f:
        while chunk := source_code.file.read(1024 * 1024):
            bytes_written += len(chunk)
            if bytes_written > MAX_SOURCE_ARCHIVE_BYTES:
                temp_dir_obj.cleanup()
                return None, None
            f.write(chunk)
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            members = zip_ref.infolist()
            if (
                len(members) > MAX_SOURCE_FILES
                or sum(member.file_size for member in members) > MAX_SOURCE_UNCOMPRESSED_BYTES
            ):
                temp_dir_obj.cleanup()
                return None, None

            extraction_root = Path(source_dir).resolve()
            for member in members:
                destination = (extraction_root / member.filename).resolve()
                if not destination.is_relative_to(extraction_root):
                    temp_dir_obj.cleanup()
                    return None, None
            zip_ref.extractall(source_dir)
        os.remove(zip_path)
        return source_dir, temp_dir_obj
    except Exception:
        temp_dir_obj.cleanup()
        return None, None


def _resolve_source_from_link(source_link: str) -> tuple[str | None, object | None, str]:
    """Clones or downloads a public GitHub repo URL into a temp dir.
    Tries git clone first, and if git is not available (like on Vercel),
    falls back to downloading the repository zipball directly."""
    parsed = urlparse(source_link)
    if parsed.scheme not in {"https", "ssh"} or not parsed.netloc:
        return None, None, "Use a valid HTTPS or SSH repository URL."

    temp_dir_obj = tempfile.TemporaryDirectory()
    source_dir = temp_dir_obj.name

    # Vercel's Python runtime normally has no git executable. Keep this
    # local-host fallback, but clone into a child because source_dir exists.
    try:
        checkout_dir = os.path.join(source_dir, "repository")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", source_link, checkout_dir],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return checkout_dir, temp_dir_obj, "Repository source loaded."
    except Exception:
        pass  # Git command not found or failed, try zipball fallback

    # Fallback for GitHub repositories (download zipball)
    if parsed.hostname == "github.com":
        try:
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
                if repo.endswith(".git"):
                    repo = repo[:-4]
                
                zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
                
                # GitHub's archive fallback works on Vercel without git.
                import requests
                headers = {"User-Agent": "redteam-in-a-box", "Accept": "application/vnd.github+json"}
                # If a GitHub token is available in env, use it to avoid rate limits
                github_token = os.getenv("GITHUB_TOKEN")
                if github_token:
                    headers["Authorization"] = f"token {github_token}"
                
                response = requests.get(zip_url, headers=headers, allow_redirects=True, timeout=20, stream=True)
                if response.status_code == 200:
                    zip_path = os.path.join(source_dir, "repo.zip")
                    bytes_written = 0
                    with open(zip_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=1024 * 1024):
                            bytes_written += len(chunk)
                            if bytes_written > MAX_SOURCE_ARCHIVE_BYTES:
                                raise ValueError("GitHub archive exceeds the 25 MB limit")
                            f.write(chunk)

                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        members = zip_ref.infolist()
                        if len(members) > MAX_SOURCE_FILES or sum(member.file_size for member in members) > MAX_SOURCE_UNCOMPRESSED_BYTES:
                            raise ValueError("GitHub archive exceeds extraction limits")
                        extraction_root = Path(source_dir).resolve()
                        if any(not (extraction_root / member.filename).resolve().is_relative_to(extraction_root) for member in members):
                            raise ValueError("GitHub archive contains an unsafe path")
                        zip_ref.extractall(source_dir)
                    os.remove(zip_path)
                    
                    # GitHub zipball extracts into a subfolder named like "owner-repo-commit/".
                    # Let's check if there's a single subdirectory and move its contents to source_dir.
                    subdirs = [d for d in Path(source_dir).iterdir() if d.is_dir()]
                    if len(subdirs) == 1:
                        nested_dir = subdirs[0]
                        for item in nested_dir.iterdir():
                            shutil.move(str(item), source_dir)
                        nested_dir.rmdir()
                    
                    return source_dir, temp_dir_obj, "GitHub repository source loaded."
                if response.status_code == 404:
                    raise ValueError("Repository was not found or is private. Use a public repository or upload a ZIP.")
                if response.status_code == 403:
                    raise ValueError("GitHub rate limit reached. Configure GITHUB_TOKEN in Vercel or upload a ZIP.")
                raise ValueError(f"GitHub returned HTTP {response.status_code}.")
        except Exception as exc:
            temp_dir_obj.cleanup()
            return None, None, str(exc)

    temp_dir_obj.cleanup()
    return None, None, "This deployment can download public GitHub repositories only. Upload a ZIP for other hosts."


@app.post("/api/scan")
async def run_scan(
    target_url: str = Form(""),
    source_code: UploadFile = File(None),
    source_link: str = Form(""),
    custom_endpoints: str = Form(""),
):
    await log_to_terminal("🚀 Starting automated red-team scanner operation...", "info")
    await log_to_terminal(f"🔗 Targeted Application endpoint: {target_url}", "info")

    source_only = not target_url.strip()
    if not source_only:
        parsed_target = urlparse(target_url)
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
            raise HTTPException(status_code=422, detail="Target URL must be a complete HTTP or HTTPS URL.")

        # Individual probes intentionally treat a missing route as clean. Check
        # connectivity once up front so an unreachable target is never reported as
        # a successful scan with zero findings.
        try:
            await asyncio.to_thread(requests.get, target_url, timeout=10, allow_redirects=True)
        except requests.RequestException as exc:
            location_hint = " Vercel cannot reach localhost on your computer; use a public deployment or tunnel URL." if parsed_target.hostname in {"localhost", "127.0.0.1"} else ""
            raise HTTPException(
                status_code=422,
                detail=f"Target is unreachable from the scanner: {exc}.{location_hint}",
            ) from exc

    # ------------------------------------------------------------------
    # Step 1: resolve source context (ZIP upload OR GitHub link, never
    # both applied - link takes precedence if both are somehow given).
    # This is ONLY read to ground suggested patches. Never modified.
    # ------------------------------------------------------------------
    source_dir = None
    temp_dir_obj = None
    source_status = "No source archive or repository was supplied."

    if source_link and source_link.strip():
        await log_to_terminal(f"🔗 Cloning source repo (read-only) for fix grounding: {source_link}", "info")
        source_dir, temp_dir_obj, source_status = _resolve_source_from_link(source_link.strip())
        if source_dir:
            await log_to_terminal("✅ Repo cloned successfully — suggestions will reference your real code.", "secure")
        else:
            await log_to_terminal("❌ Could not clone repo link. Continuing without source grounding.", "alert")
    elif source_code and source_code.filename and source_code.filename.endswith(".zip"):
        await log_to_terminal("📦 Source code ZIP provided. Extracting (read-only) for fix grounding...", "info")
        source_dir, temp_dir_obj = _resolve_source_from_zip(source_code)
        if source_dir:
            await log_to_terminal("✅ Source code extracted successfully.", "secure")
        else:
            await log_to_terminal("❌ Failed to extract ZIP. Continuing without source grounding.", "alert")

    if source_only:
        if not source_dir:
            raise HTTPException(
                status_code=422,
                detail="Provide a public GitHub repository link or a ZIP archive for source review.",
            )
        await log_to_terminal("Reviewing repository source with static checks...", "info")
        findings = await asyncio.to_thread(scan_source, source_dir)
        await log_to_terminal(f"Source review found {len(findings)} item(s) to verify.", "info")
        report = []
        for finding in findings:
            entry = {**finding, "cvss": calculate_severity(finding), "analysis": await analyze_finding(finding, source_dir)}
            report.append(entry)
        report.sort(key=lambda item: item["cvss"].get("score", 0), reverse=True)
        for entry in report:
            await broadcast({"event": "finding", "data": entry})
        coverage = build_coverage(report)
        assessment = await summarize_assessment(report, coverage)
        await broadcast({"event": "assessment", "data": {"coverage": coverage, "summary": assessment}})
        await broadcast({"event": "chains", "data": []})
        await broadcast({"event": "scan_complete", "data": {"total_findings": len(report)}})
        if temp_dir_obj:
            temp_dir_obj.cleanup()
        return {"target": "Repository source review", "findings": report, "chains": [], "coverage": coverage, "summary": assessment, "source_status": source_status}

    # ------------------------------------------------------------------
    # Step 2: known demo-specific modules. These target exact routes
    # from the bundled vulnerable-app - they simply find nothing (safe
    # no-op) against any other target, so it's harmless to always run them.
    # ------------------------------------------------------------------
    findings = []

    known_checks = [
        ("[Known routes] SQL Injection on /login", sqli.test_sqli),
        ("[Known routes] IDOR on /api/user/:id", idor.test_idor),
        ("[Known routes] Broken Access Control on /admin/users", auth_bypass.test_auth_bypass),
        ("[Known routes] Reflected XSS on /comment", xss.test_xss),
        ("[Known routes] Path Traversal on /api/file", path_traversal.test_path_traversal),
        ("[Known routes] Command Injection on /api/ping", command_injection.test_command_injection),
        ("[Known routes] SSRF on /api/fetch-url", ssrf.test_ssrf),
    ]
    for label, fn in known_checks:
        await log_to_terminal(f"🔍 {label}...", "scanning")
        result = await asyncio.to_thread(fn, target_url)
        if result:
            await log_to_terminal(f"🔥 {result[0]['type']} confirmed on known route.", "alert")
            findings.extend(result)
        else:
            await log_to_terminal("✅ Clean.", "secure")

    # ------------------------------------------------------------------
    # Step 3: generic blackbox testing - THIS is what makes the scanner
    # work against any app, not just the bundled demo. Crawl the target,
    # merge in any endpoints the user already knows about, then run the
    # generic heuristic attack modules against the combined list.
    # ------------------------------------------------------------------
    await log_to_terminal("🕷️ Crawling target for generic endpoint discovery...", "info")
    crawled = await asyncio.to_thread(recon.crawl, target_url)

    parsed_custom = []
    if custom_endpoints and custom_endpoints.strip():
        try:
            parsed_custom = json.loads(custom_endpoints)
            if not isinstance(parsed_custom, list):
                parsed_custom = []
        except json.JSONDecodeError:
            await log_to_terminal("⚠️ Custom endpoints JSON could not be parsed - skipping.", "alert")

    all_endpoints = recon.merge_custom_endpoints(crawled, parsed_custom)
    await log_to_terminal(f"🕸️ Discovered {len(all_endpoints)} testable endpoint(s) total.", "info")

    passive_checks = [
        ("Browser security headers", passive.test_security_headers),
        ("Unsafe CORS policy", passive.test_permissive_cors),
        ("Exposed error details", passive.test_information_disclosure),
    ]
    for label, fn in passive_checks:
        await log_to_terminal(f"🔎 Checking {label.lower()}...", "scanning")
        result = await asyncio.to_thread(fn, target_url)
        if result:
            await log_to_terminal(f"⚠️ {result[0]['type']} found. Review the suggested change.", "alert")
            findings.extend(result)
        else:
            await log_to_terminal("✅ No issue found.", "secure")

    generic_checks = [
        ("Generic SQL Injection sweep", generic.test_generic_sqli),
        ("Generic XSS sweep", generic.test_generic_xss),
        ("Generic Path Traversal sweep", generic.test_generic_path_traversal),
        ("Generic SSRF sweep", generic.test_generic_ssrf),
        ("Generic Command Injection sweep (timing-based)", generic.test_generic_command_injection),
    ]
    for label, fn in generic_checks:
        await log_to_terminal(f"🔍 {label} across all discovered endpoints...", "scanning")
        result = await asyncio.to_thread(fn, all_endpoints)
        if result:
            await log_to_terminal(f"🔥 {label} found {len(result)} issue(s)!", "alert")
            findings.extend(result)
        else:
            await log_to_terminal("✅ Clean.", "secure")

    # ------------------------------------------------------------------
    # Step 4: exploit chain detection + scoring (unchanged logic)
    # ------------------------------------------------------------------
    await log_to_terminal("⚙️ Analyzing findings for exploit chains...", "info")
    chains = find_chains(findings)
    mark_chained_findings(findings, chains)

    if chains:
        await log_to_terminal(f"⛓ Found {len(chains)} exploit chaining route(s)! Severities escalated.", "alert")
    else:
        await log_to_terminal("✅ No exploit paths could be chained.", "secure")

    report = []
    for finding in findings:
        cvss = calculate_severity(finding)
        analysis = await analyze_finding(finding, source_dir)
        entry = {**finding, "cvss": cvss, "analysis": analysis}
        report.append(entry)
    report.sort(key=lambda item: item["cvss"].get("score", 0), reverse=True)
    for entry in report:
        await broadcast({"event": "finding", "data": entry})

    coverage = build_coverage(report)
    assessment = await summarize_assessment(report, coverage)
    await broadcast({"event": "assessment", "data": {"coverage": coverage, "summary": assessment}})
    await broadcast({"event": "chains", "data": chains})
    await broadcast({"event": "scan_complete", "data": {"total_findings": len(report)}})

    await log_to_terminal("🏁 Scanner execution finished. Report ready to download.", "info")

    if temp_dir_obj:
        temp_dir_obj.cleanup()

    return {"target": target_url, "findings": report, "chains": chains, "coverage": coverage, "summary": assessment, "source_status": source_status}
