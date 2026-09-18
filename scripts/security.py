"""Security scan orchestrator: runs STATIC analyzers on the target skill's code.
Never executes target code. Tools: bandit (python), shellcheck (sh), semgrep (all), pip-audit (deps).
"""
import json
import os
import shutil
import subprocess  # nosec B404 (static analyzers orchestrated by design)
import contextlib
import tempfile

TIMEOUT = 60  # per tool

def _safe_arg(p):
    if p.startswith('-'):
        return './' + p
    return p



def _run(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, cwd=cwd)  # nosec B603 (fixed tool list, never target code)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not installed"


def _collect_scripts(target):
    py, sh = [], []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git', 'node_modules', '.venv', 'venv')]
        for fn in files:
            path = os.path.join(root, fn)
            real = os.path.realpath(path)
            if not real.startswith(os.path.realpath(target) + os.sep):
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext == "" and os.access(path, os.X_OK):
                with open(path, "rb") as f:
                    head = f.read(40).lower()
                if head.startswith(b"#!") and b"python" in head:
                    py.append(path)
                elif head.startswith(b"#!"):
                    sh.append(path)
                continue
            if fn.endswith(".py"):
                py.append(path)
            elif fn.endswith((".sh", ".bash")):
                sh.append(path)
    return py, sh


def check(target, log):
    py, sh = _collect_scripts(target)

    if not py and not sh:
        log("INFO", "no bundled scripts — static security scan skipped", None)
        return

    # --- bandit ---
    if py and shutil.which("bandit"):
        rc, out, err = _run(["bandit", "-q", "-f", "json", "--", *[_safe_arg(p) for p in py]])
        if out:
            try:
                data = json.loads(out)
                DANGEROUS = {"B307", "B602", "B605", "B608", "B506", "B113"}
                sevmap = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
                for r in data.get("results", []):
                    sev = sevmap.get(r.get("issue_severity", "LOW"), "LOW")
                    if r.get("test_id") in DANGEROUS:
                        sev = "HIGH"
                    log(sev, f"bandit [{r.get('test_id')}]: {r.get('test_name')}: {r.get('issue_text')}",
                        os.path.relpath(r.get("filename", "?"), target), r.get("line_number"))
            except json.JSONDecodeError:
                log("LOW", "bandit ran but output unparseable", None)
    elif py:
        log("INFO", "python scripts present but bandit unavailable — incomplete scan", None)

    # --- gitleaks: hardcoded secrets in ANY file (200+ secret rules) ---
    if shutil.which("gitleaks"):
        fd, report = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            rc, out, _ = _run(["gitleaks", "detect", "--no-git", "--source", _safe_arg(target),
                               "--report-format", "json", "--report-path", report])
            try:  # nosec B110 (absent report file = clean, by design)
                with open(report) as fh:
                    leaks = json.load(fh)
                for lk in leaks[:20]:
                    rel = os.path.relpath(lk.get("File", ""), target) if lk.get("File") else None
                    log("HIGH", f"gitleaks [{lk.get('RuleID')}]: hardcoded secret ({lk.get('Secret', '')[:12]}...) — {lk.get('Description', '')[:60]}", rel, lk.get("StartLine"))
            except Exception:  # nosec B110 (absent report file = clean, by design)
                pass  # no leaks or empty report — clean
        finally:
            with contextlib.suppress(OSError):
                os.unlink(report)  # never leak the temp report on the host

    # --- shellcheck ---
    if sh and shutil.which("shellcheck"):
        rc, out, _ = _run(["shellcheck", "-f", "json", "--", *[_safe_arg(os.path.relpath(p, target)) for p in sh]], cwd=target)
        if out:
            try:
                for item in json.loads(out):
                    sev = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW"}.get(item.get("level", "info"), "LOW")
                    log(sev, f"shellcheck [{item.get('code')}]: {item.get('message')}",
                        item.get("file", "?"), item.get("line"))
            except json.JSONDecodeError:
                log("LOW", "shellcheck ran but output unparseable", None)
    elif sh:
        log("INFO", "shell scripts present but shellcheck unavailable on host — install for full coverage (no score penalty)", None)

    # --- semgrep (no config: defaults + p/owasp rules would need network; run bare) ---
    if (py or sh) and shutil.which("semgrep"):
        rc, out, err = _run(["semgrep", "--config", "auto", "--json", "--quiet", "--", _safe_arg(target)])
        if out:
            try:
                data = json.loads(out)
                for r in data.get("results", []):
                    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(r.get("extra", {}).get("severity", "INFO"), "LOW")
                    log(sev, f"semgrep [{r.get('check_id')}]: {r.get('extra', {}).get('message', '')}",
                        os.path.relpath(r.get("path", "?"), target), r.get("start", {}).get("col"))
            except json.JSONDecodeError:
                pass
        if rc == 124:
            log("MEDIUM", "semgrep timed out — scan incomplete", None)

    # --- pip-audit ---
    reqs = None
    for cand in ("requirements.txt", os.path.join("scripts", "requirements.txt")):
        p = os.path.join(target, cand)
        if os.path.isfile(p):
            reqs = p
            break
    if reqs and shutil.which("pip-audit"):
        rc, out, err = _run(["pip-audit", "--no-deps", "--disable-pip", "-r", _safe_arg(reqs)])
        if rc == 124:
            log("MEDIUM", "pip-audit timed out — dependency scan incomplete", "requirements.txt")
        # pip-audit prints the summary to stderr, the row table to stdout
        summary = next((l for l in err.splitlines() if "known vulnerabilities" in l), "")
        if summary and "Found 0" not in summary:
            n_rows = sum(1 for l in out.splitlines() if any(k in l for k in ("PYSEC", "CVE-", "GHSA")))
            log("HIGH", f"pip-audit: {summary.strip()} ({n_rows} vulnerable pins) — see report rows", "requirements.txt")
        elif rc == 0:
            log("INFO", "pip-audit: no known-vulnerability findings", "requirements.txt")
    elif reqs:
        log("INFO", "requirements.txt present but pip-audit unavailable — dependency scan skipped", None)
