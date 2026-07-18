"""Conservative static checks for repository-only source reviews."""
import re
from pathlib import Path

SOURCE_EXTENSIONS = {".js", ".ts", ".tsx", ".py", ".java", ".go", ".rb", ".php", ".cs"}


def _finding(kind: str, path: Path, root: Path, line_number: int, line: str, evidence: str) -> dict:
    return {
        "type": kind,
        "endpoint": f"{path.relative_to(root)}:{line_number}",
        "method": "SOURCE",
        "evidence": f"{evidence} Matched code: {line.strip()[:220]}",
        "requires_auth": False,
        "produces": [],
        "requires": [],
    }


def _match(line: str, suffix: str) -> tuple[str, str] | None:
    lowered = line.lower()
    # Only report patterns where a sensitive API is combined with obviously
    # dynamic input. This avoids flagging UI methods such as setIsOpen(true).
    if re.search(r"\b(select|insert|update|delete)\b.*(\$\{|\+|f['\"]|format\()", line, re.I):
        return "SQL Injection", "A SQL statement is built with dynamic input; use parameter bindings instead."
    if ("child_process.exec" in lowered or re.search(r"\bexec\s*\(", lowered)) and ("${" in line or "+" in line or "shell=true" in lowered):
        return "Command Injection", "A command-execution API receives dynamic input; use an allowlist and avoid shell execution."
    if "dangerouslysetinnerhtml" in lowered or ("res.send(" in lowered and ("req." in lowered or "${" in line)):
        return "Reflected XSS", "HTML output includes dynamic content; encode untrusted values for their output context."
    if suffix in {".js", ".ts", ".tsx"} and re.search(r"(sendfile|readfile|createReadStream)\s*\(.*(req\.|\$\{|\+)", line, re.I):
        return "Path Traversal", "A file API receives dynamic request input; resolve and enforce an allowed base directory."
    if suffix == ".py" and re.search(r"\bopen\s*\(.*(request\.|args\.|form\[|f['\"]|\+)", line, re.I):
        return "Path Traversal", "A file API receives dynamic request input; resolve and enforce an allowed base directory."
    return None


def scan(source_dir: str) -> list[dict]:
    root = Path(source_dir)
    findings = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if any(part.startswith(".") or part in {"node_modules", "vendor", "dist", "build"} for part in path.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            matched = _match(line, path.suffix.lower())
            if matched:
                kind, evidence = matched
                findings.append(_finding(kind, path, root, line_number, line, evidence))
    return findings
