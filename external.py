"""
external.py - optional extra scanners. CodeGuard works fully without them; when they are installed
(from the USB bundle) their findings are added to the same list, marked with the tool's name.

    Bandit   - Python security linter            (pip package, run as  python -m bandit)
    Semgrep  - rule-based scanner, Python + JS    (needs a local rules folder; never downloads rules)
    Gitleaks - secrets scanner                    (gitleaks.exe)
    ClamAV   - antivirus                          (clamscan.exe, with its offline signature files)

Every tool runs with a time limit, and any failure is reported as a note, never as a crash.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

SEV = {"low": "low", "medium": "medium", "high": "high", "critical": "critical", "info": "info",
       "warning": "medium", "error": "high", "undefined": "low"}


def _run(cmd, timeout):
    # Arguments are always passed as a list (no shell), so paths with spaces or symbols are safe.
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")


def _exe(setting, name):
    p = (setting or "").strip()
    if p and os.path.isfile(p):
        return p
    return shutil.which(name)


def available(settings):
    tools = {}
    try:
        import importlib.util
        tools["bandit"] = importlib.util.find_spec("bandit") is not None
    except Exception:
        tools["bandit"] = False
    tools["semgrep"] = bool(_exe(settings.get("semgrep_path"), "semgrep")) and \
        os.path.isdir(settings.get("semgrep_rules") or "")
    tools["gitleaks"] = bool(_exe(settings.get("gitleaks_path"), "gitleaks"))
    tools["clamav"] = bool(_exe(settings.get("clamscan_path"), "clamscan"))
    return tools


def _rel(root, path):
    try:
        return os.path.relpath(os.path.abspath(path), root).replace("\\", "/")
    except ValueError:
        return path


def run_all(root, settings, excluded_dirs, timeout=600):
    """-> (findings, notes). Findings carry 'file', 'rule', 'line', 'msg', 'severity', 'tool'."""
    tools = available(settings)
    findings, notes = [], []
    if not settings.get("external_tools_enabled", True):
        return findings, notes
    if tools.get("bandit"):
        try:
            r = _run([sys.executable, "-m", "bandit", "-r", root, "-f", "json", "-q",
                      "-x", ",".join(os.path.join(root, d) for d in excluded_dirs)], timeout)
            data = json.loads(r.stdout or "{}")
            for it in data.get("results", []):
                findings.append({"tool": "Bandit", "rule": "EXT001", "file": _rel(root, it.get("filename", "")),
                                 "line": it.get("line_number", 0), "severity": SEV.get(str(it.get("issue_severity", "")).lower(), "low"),
                                 "msg": "Bandit %s: %s" % (it.get("test_id"), it.get("issue_text"))})
        except Exception as e:
            notes.append("Bandit could not run: %s" % e)
    if tools.get("semgrep"):
        try:
            r = _run([_exe(settings.get("semgrep_path"), "semgrep"), "scan", "--config", settings["semgrep_rules"],
                      "--json", "--metrics=off", "--disable-version-check", "--quiet", root], timeout)
            data = json.loads(r.stdout or "{}")
            for it in data.get("results", []):
                ex = it.get("extra", {})
                findings.append({"tool": "Semgrep", "rule": "EXT001", "file": _rel(root, it.get("path", "")),
                                 "line": (it.get("start") or {}).get("line", 0),
                                 "severity": SEV.get(str(ex.get("severity", "")).lower(), "medium"),
                                 "msg": "Semgrep %s: %s" % (it.get("check_id", "").split(".")[-1], ex.get("message", ""))})
        except Exception as e:
            notes.append("Semgrep could not run: %s" % e)
    if tools.get("gitleaks"):
        try:
            fd, rep = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            _run([_exe(settings.get("gitleaks_path"), "gitleaks"), "detect", "--no-git", "-s", root, "-f", "json",
                  "-r", rep, "--exit-code", "0", "--no-banner"], timeout)
            with open(rep, encoding="utf-8") as fh:
                data = json.load(fh) if os.path.getsize(rep) else []
            os.remove(rep)
            for it in data or []:
                sec = str(it.get("Secret", ""))
                findings.append({"tool": "Gitleaks", "rule": "EXT001", "file": _rel(root, it.get("File", "")),
                                 "line": it.get("StartLine", 0), "severity": "high", "secret": sec,
                                 "msg": "Gitleaks %s: %s" % (it.get("RuleID"), it.get("Description", ""))})
        except Exception as e:
            notes.append("Gitleaks could not run: %s" % e)
    if tools.get("clamav"):
        try:
            r = _run([_exe(settings.get("clamscan_path"), "clamscan"), "-r", "--infected", "--no-summary", root],
                     max(timeout, 1800))
            for ln in (r.stdout or "").splitlines():
                if ln.endswith(" FOUND") and ": " in ln:
                    path, sig = ln.rsplit(": ", 1)
                    findings.append({"tool": "ClamAV", "rule": "MAL005", "file": _rel(root, path), "line": 0,
                                     "msg": "ClamAV: %s" % sig.replace(" FOUND", "")})
        except Exception as e:
            notes.append("ClamAV could not run: %s" % e)
    return findings, notes
