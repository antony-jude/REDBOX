"""
Main orchestrator - FastAPI server for AI Red-Team-in-a-Box.

Flow on POST /api/scan:
  1. Trigger new modules (SQLi, IDOR, Auth Bypass, XSS, Path Traversal, Command Injection, SSRF).
  2. Stream step-by-step logs to the client terminal over WebSockets.
  3. Detect multi-hop chains and programmatically score.
"""
import os
import asyncio
import requests
import tempfile
import shutil
import zipfile
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from attacks import sqli, idor, auth_bypass, xss, path_traversal, command_injection, ssrf
from chain_engine import find_chains, mark_chained_findings
from cvss_scorer import calculate_severity
from llm_analyzer import analyze_finding

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
    # Small delay for realistic terminal streaming effect
    await asyncio.sleep(0.15)


@app.get("/api/health")
async def health():
    return {"status": "ok", "target": TARGET_URL, "llm_enabled": bool(os.getenv("ANTHROPIC_API_KEY"))}


@app.post("/api/scan")
async def run_scan(
    target_url: str = Form(...),
    source_code: UploadFile = File(None)
):
    await log_to_terminal("🚀 Starting generic automated red-team scanner operation...", "info")
    await log_to_terminal(f"🔗 Targeted Application endpoint: {target_url}", "info")
    
    # Extract zip if provided
    source_dir = None
    temp_dir_obj = None
    if source_code and source_code.filename and source_code.filename.endswith(".zip"):
        await log_to_terminal("📦 Source code ZIP provided. Extracting for SAST-enhanced patching...", "info")
        temp_dir_obj = tempfile.TemporaryDirectory()
        source_dir = temp_dir_obj.name
        
        # Save and extract
        zip_path = os.path.join(source_dir, "upload.zip")
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(source_code.file, f)
            
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(source_dir)
            os.remove(zip_path)
            await log_to_terminal("✅ Source code extracted successfully.", "secure")
        except Exception as e:
            await log_to_terminal(f"❌ Failed to extract ZIP: {e}", "alert")
            source_dir = None

    # Run active tests sequentially to emit logs for each target path
    findings = []
    
    # 1. SQL Injection
    await log_to_terminal("🔍 [1/7] Injecting SQL Auth Bypass payloads into /login...", "scanning")
    res_sqli = sqli.test_sqli(target_url)
    if res_sqli:
        await log_to_terminal("🔥 SQL Injection detected! Response matches success query signature.", "alert")
        findings.extend(res_sqli)
    else:
        await log_to_terminal("✅ SQL Injection test clean.", "secure")

    # 2. IDOR
    await log_to_terminal("🔍 [2/7] Probing /api/user/:id endpoint for IDOR object reference...", "scanning")
    res_idor = idor.test_idor(target_url)
    if res_idor:
        await log_to_terminal("🔥 IDOR vulnerability found! Exposed third party user record data.", "alert")
        findings.extend(res_idor)
    else:
        await log_to_terminal("✅ IDOR test clean.", "secure")

    # 3. Broken Access Control
    await log_to_terminal("🔍 [3/7] Accessing admin portal /admin/users with zero headers...", "scanning")
    res_auth = auth_bypass.test_auth_bypass(target_url)
    if res_auth:
        await log_to_terminal("🔥 Broken Access Control found! Admin list returned on unauthorized request.", "alert")
        findings.extend(res_auth)
    else:
        await log_to_terminal("✅ Broken Access Control test clean.", "secure")

    # 4. Reflected XSS
    await log_to_terminal("🔍 [4/7] Injecting javascript probe scripts into /comment...", "scanning")
    res_xss = xss.test_xss(target_url)
    if res_xss:
        await log_to_terminal("🔥 Reflected XSS payload reflection confirmed.", "alert")
        findings.extend(res_xss)
    else:
        await log_to_terminal("✅ XSS test clean.", "secure")

    # 5. Path Traversal
    await log_to_terminal("🔍 [5/7] Sending path traversal payloads to /api/file...", "scanning")
    res_traversal = path_traversal.test_path_traversal(target_url)
    if res_traversal:
        await log_to_terminal("🔥 Path Traversal vulnerability detected! Retrieved package configuration.", "alert")
        findings.extend(res_traversal)
    else:
        await log_to_terminal("✅ Path Traversal test clean.", "secure")

    # 6. Command Injection
    await log_to_terminal("🔍 [6/7] Injecting shell command separators into /api/ping...", "scanning")
    res_cmd = command_injection.test_command_injection(target_url)
    if res_cmd:
        await log_to_terminal("🔥 Command Injection active! Executed command shell returns successfully.", "alert")
        findings.extend(res_cmd)
    else:
        await log_to_terminal("✅ Command Injection test clean.", "secure")

    # 7. SSRF
    await log_to_terminal("🔍 [7/7] Injecting internal service loopback links into /api/fetch-url...", "scanning")
    res_ssrf = ssrf.test_ssrf(target_url)
    if res_ssrf:
        await log_to_terminal("🔥 SSRF confirmed! Retrieved scanner engine health metadata.", "alert")
        findings.extend(res_ssrf)
    else:
        await log_to_terminal("✅ SSRF test clean.", "secure")

    # Chaining analysis
    await log_to_terminal("⚙️ Scanning completed. Analyzing target vulnerabilities for exploit chains...", "info")
    chains = find_chains(findings)
    mark_chained_findings(findings, chains)
    
    if chains:
        await log_to_terminal(f"⛓ Found {len(chains)} exploit chaining routes! Severities escalated.", "alert")
    else:
        await log_to_terminal("✅ No exploit paths could be chained.", "secure")

    # Score and broadcast results
    report = []
    for finding in findings:
        cvss = calculate_severity(finding)
        analysis = await analyze_finding(finding, source_dir)
        entry = {**finding, "cvss": cvss, "analysis": analysis}
        report.append(entry)
        await broadcast({"event": "finding", "data": entry})

    await broadcast({"event": "chains", "data": chains})
    await broadcast({"event": "scan_complete", "data": {"total_findings": len(report)}})
    
    await log_to_terminal("🏁 Scanner execution finished. Report updated.", "info")

    if temp_dir_obj:
        temp_dir_obj.cleanup()

    return {"target": target_url, "findings": report, "chains": chains}




