"""Small, conservative static checks for repository-only source reviews."""
from pathlib import Path

SOURCE_EXTENSIONS = {".js", ".ts", ".tsx", ".py", ".java", ".go", ".rb", ".php", ".cs"}


def scan(source_dir: str) -> list[dict]:
    checks = (
        ("SQL Injection", ("select ", "execute(", "cursor.execute", "query("), "SQL-like query construction was found; verify values are parameterized."),
        ("Command Injection", ("child_process.exec", "exec(", "subprocess.run", "os.system("), "A process-execution API was found; verify untrusted input cannot reach a shell."),
        ("Reflected XSS", ("res.send(", "innerhtml", "dangerouslysetinnerhtml"), "HTML rendering code was found; verify untrusted values are escaped."),
        ("Path Traversal", ("sendfile(", "sendfile", "readfile(", "open("), "File-access code was found; verify paths are constrained to an allowed directory."),
    )
    findings = []
    for path in Path(source_dir).rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if any(part.startswith(".") or part in {"node_modules", "vendor", "dist", "build"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = text.lower()
        for finding_type, patterns, evidence in checks:
            if any(pattern in lowered for pattern in patterns):
                findings.append({
                    "type": finding_type,
                    "endpoint": str(path.relative_to(source_dir)),
                    "method": "SOURCE",
                    "evidence": evidence,
                    "requires_auth": False,
                    "produces": [],
                    "requires": [],
                })
                break
    return findings
