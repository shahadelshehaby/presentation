"""
scan_text.py - pattern checks for web pages (.html/.js), Windows scripts (.bat/.cmd/.ps1),
secrets in every text file, malware signs and suspicious file names.

All functions return lists of {"rule", "line", "msg", optional "severity", optional "secret"}.
"secret" is the exact text to hide (mask) in the stored code line, so passwords never reach the
database or the reports.
"""
import os
import re

CODE_EXT = {".py", ".js", ".html", ".htm", ".bat", ".cmd", ".ps1", ".vbs", ".sh"}
CONFIG_EXT = {".json", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".env", ".properties", ".xml"}
DOC_EXT = {".md", ".txt", ".rst", ".csv"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".msi", ".msp",
            ".pif", ".cpl", ".sys", ".drv", ".lnk", ".reg", ".ps1", ".psm1"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|csv|txt|jpe?g|png|gif|mp4|avi|zip|rar)\.(exe|scr|com|bat|cmd|vbs|js|jar|"
                        r"pif|lnk|hta|ps1)$", re.I)

PLACEHOLDERS = {"", "pass", "password", "passwd", "pwd", "secret", "token", "changeme_placeholder", "xxx", "xxxx",
                "xxxxx", "***", "****", "*****", "none", "null", "true", "false", "your_password", "yourpassword",
                "<password>", "password_here", "example", "test", "user", "username", "admin_password", "mypassword",
                "text", "string", "hidden", "off", "on"}


def _ignored(line):
    return "codeguard: ignore" in line or "# nosec" in line


def _placeholder(value, key=""):
    v = value.strip().strip("'\"")
    lv = v.lower()
    if lv in PLACEHOLDERS or lv == key.lower():
        return True
    if any(c in v for c in "{}%$<>") or v.startswith(("os.", "env", "getenv", "self.", "cfg", "config", "settings")):
        return True
    if " " in v.strip():          # labels like "Show password" or "Enter your token"
        return True
    if set(v) <= set("*xX#.-_"):
        return True
    if re.fullmatch(r"[(\[<].*[)\]>]", v):    # display placeholders like (set) or <hidden>
        return True
    return False


def _mask(v):
    v = str(v)
    return (v[:2] + "****") if len(v) > 2 else "****"


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


# =============================================================== secrets (all text files)
URL_CRED = re.compile(r"\b([a-z][a-z0-9+.\-]{1,15})://([^\s:/@'\"<>{}()]{1,64}):([^\s@/'\"<>]{1,128})@", re.I)
KEY_ASSIGN = re.compile(r"""(?i)["']?\b([\w.\-]*?(password|passwd|pwd|passcode|(?<![a-z])pass(?![a-z])|secret|token|api[_\-]?key|"""
                        r"""access[_\-]?key|auth[_\-]?key|private[_\-]?key|client[_\-]?secret)[\w.\-]*)["']?\s*"""
                        r"""(?:=|:|=>)\s*(["'])([^"'\n]{4,200})\3""")
INI_ASSIGN = re.compile(r"""(?im)^\s*([\w.\-]*(password|passwd|pwd|(?<![a-z])pass(?![a-z])|secret|token|api_?key)[\w.\-]*)\s*[=:]\s*"""
                        r"""([^\s#;'"]{4,200})\s*$""")
TOKENS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bsk-(ant-)?[A-Za-z0-9_\-]{24,}\b"), "AI service API key"),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----")


def scan_secrets(text, ext):
    out = []
    lines = text.splitlines()
    is_doc = ext in DOC_EXT
    is_cfg = ext in CONFIG_EXT
    for i, ln in enumerate(lines, 1):
        if _ignored(ln) or len(ln) > 4000:
            continue
        for m in URL_CRED.finditer(ln):
            scheme, user, pw = m.group(1), m.group(2), m.group(3)
            if _placeholder(pw) or scheme.lower() in ("data", "mailto"):
                continue
            out.append({"rule": "SEC001", "line": i, "secret": pw,
                        "msg": "%s:// address contains user '%s' and a password (%s)." % (scheme, user, _mask(pw)),
                        "severity": "low" if is_doc else None})
        for m in KEY_ASSIGN.finditer(ln):
            key, val = m.group(1), m.group(4)
            if _placeholder(val, key) or "type" == key.lower():
                continue
            if re.match(r"(?i)^(input|label|placeholder|show|hide|reset|forgot|confirm|new|old|field)", key) and \
                    len(val) < 25 and not re.search(r"\d", val):
                continue
            rule = "SEC005" if is_cfg else "SEC002"
            out.append({"rule": rule, "line": i, "secret": val,
                        "msg": "'%s' holds a literal value (%s)." % (key, _mask(val)),
                        "severity": "low" if is_doc else None})
        for rx, label in TOKENS:
            m = rx.search(ln)
            if m:
                out.append({"rule": "SEC004", "line": i, "secret": m.group(0),
                            "msg": "%s found (%s)." % (label, _mask(m.group(0)))})
    if is_cfg or ext in (".env", ".ini", ".cfg", ".conf", ".properties", ""):
        for m in INI_ASSIGN.finditer(text):
            key, val = m.group(1), m.group(3)
            if _placeholder(val, key):
                continue
            line = _line_of(text, m.start())
            if any(f["line"] == line for f in out):
                continue
            out.append({"rule": "SEC005", "line": line, "secret": val,
                        "msg": "'%s' holds a password-like value (%s)." % (key, _mask(val))})
    m = PRIVATE_KEY.search(text)
    if m:
        out.append({"rule": "SEC003", "line": _line_of(text, m.start()), "msg": "A private key block is stored here."})
    return out


# =============================================================== web pages
JS_RULES = [
    ("JS002", re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|set(Timeout|Interval)\(\s*['\"`]"),
     "Text is executed as JavaScript."),
    ("JS004", re.compile(r"document\.write(ln)?\s*\("), "document.write(...) used."),
    ("JS005", re.compile(r"(localStorage|sessionStorage)\.setItem\(\s*['\"][^'\"]*(pass|pwd|token|secret|pin)[^'\"]*['\"]",
                         re.I), "A password/token is stored in browser storage."),
]
INNER = re.compile(r"\.(innerHTML|outerHTML)\s*\+?=\s*(.*)|insertAdjacentHTML\s*\((.*)")
EXT_SRC = re.compile(r"<(script|link|img|iframe)\b[^>]*?\b(src|href)\s*=\s*[\"'](https?:)?//([^/\"'>]+)[^\"'>]*[\"']"
                     r"[^>]*>|@import\s+url\(\s*['\"]?https?://([^/'\")]+)", re.I)
LOCAL_HOST = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1)")


def scan_web(text):
    out = []
    lines = text.splitlines()
    inner = []
    for i, ln in enumerate(lines, 1):
        if _ignored(ln):
            continue
        for rid, rx, msg in JS_RULES:
            if rx.search(ln):
                out.append({"rule": rid, "line": i, "msg": msg})
        m = INNER.search(ln)
        if m:
            rhs = m.group(2) or m.group(3) or ""
            dynamic = "${" in rhs or re.search(r"[\"'`]\s*\+\s*[\w(]|[\w)\]]\s*\+\s*[\"'`]", rhs) or \
                re.match(r"\s*[A-Za-z_$][\w.$\[\]]*\s*;?\s*$", rhs)
            escaped = re.search(r"\b(esc|escape|escapeHtml|escHtml|sanitize|DOMPurify|h)\s*\(", rhs)
            if dynamic and not escaped and not re.match(r"\s*['\"`]{2}\s*;?\s*$", rhs):
                inner.append(i)
        if re.search(r"target\s*=\s*[\"']_blank[\"']", ln, re.I) and not re.search(r"noopener", ln, re.I):
            out.append({"rule": "JS006", "line": i, "msg": "target=\"_blank\" without rel=\"noopener\"."})
    for m in EXT_SRC.finditer(text):
        host = m.group(4) or m.group(5) or ""
        if LOCAL_HOST.match(host):
            continue
        tag = m.group(0)
        line = _line_of(text, m.start())
        if _ignored(lines[line - 1] if line - 1 < len(lines) else ""):
            continue
        if (m.group(1) or "").lower() == "link" and not re.search(r"stylesheet|preload|modulepreload", tag, re.I):
            continue
        sev = "low" if re.search(r"integrity\s*=", tag, re.I) else None
        out.append({"rule": "JS003", "line": line, "msg": "Loads %s from the internet (%s)." % (
            "a file" if not m.group(1) else "<%s>" % m.group(1).lower(), host), "severity": sev})
    if inner:
        if len(inner) <= 6:
            for ln in inner:
                out.append({"rule": "JS001", "line": ln, "msg": "innerHTML is built from variables without escaping."})
        else:
            out.append({"rule": "JS001", "line": inner[0],
                        "msg": "%d places build HTML from variables without escaping (lines %s)."
                               % (len(inner), ", ".join(map(str, inner[:15])) + (" ..." if len(inner) > 15 else ""))})
    # collapse many JS006 into one
    j6 = [f for f in out if f["rule"] == "JS006"]
    if len(j6) > 3:
        out = [f for f in out if f["rule"] != "JS006"]
        out.append({"rule": "JS006", "line": j6[0]["line"], "msg": "%d links open new tabs without rel=noopener." % len(j6)})
    return out


# =============================================================== Windows scripts
BAT_RULES = [
    ("BAT002", re.compile(r"-ExecutionPolicy\s+(Bypass|Unrestricted)|\bIEX\b|Invoke-Expression|DownloadString|"
                          r"DownloadFile|-EncodedCommand|\s-enc\s", re.I), "PowerShell bypass or download-and-run."),
    ("BAT003", re.compile(r"\b(curl|wget)(\.exe)?\s[^\n]*https?://|Invoke-WebRequest|\biwr\s|bitsadmin\s+/transfer|"
                          r"certutil[^\n]*-urlcache|Start-BitsTransfer", re.I), "Downloads a file from the internet."),
    ("BAT004", re.compile(r"schtasks\s+/create|\breg\s+add\b|\bnet\s+user\b|\\Start Menu\\Programs\\Startup|"
                          r"\\Startup\\|Register-ScheduledTask|New-ScheduledTask|\bsc\s+create\b|"
                          r"CurrentVersion\\Run", re.I), "Changes Windows start-up, tasks, registry or accounts."),
]
PIP = re.compile(r"\bpip3?(\.exe)?\s+install\b|-m\s+pip\s+install\b", re.I)


def scan_script(text):
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        if not s or _ignored(ln) or s.lower().startswith(("rem ", "::", "#")):
            continue
        if PIP.search(ln) and "--no-index" not in ln and not re.search(r"--find-links|-f\s", ln):
            out.append({"rule": "BAT001", "line": i, "msg": "pip install from the internet: %s" % s[:120]})
        for rid, rx, msg in BAT_RULES:
            if rx.search(ln):
                out.append({"rule": rid, "line": i, "msg": msg + "  " + s[:120]})
    return out


# =============================================================== malware signs (code files)
REVERSE_SHELL = re.compile(  # codeguard: ignore - these are detection signatures, not code that runs
    r"socket\.socket\([\s\S]{0,400}?(os\.dup2|pty\.spawn|/bin/(ba)?sh|cmd\.exe|subprocess\.(Popen|call)\([^)]*stdin\s*=)|"
    r"\bnc(\.exe)?\s+(-[a-z]*e\s|.*\s-e\s)|bash\s+-i\s+>&\s*/dev/tcp/|New-Object\s+System\.Net\.Sockets\.TCPClient|"
    r"powercat|meterpreter|mimikatz", re.I)  # codeguard: ignore - signature list
BLOB = re.compile(r"[A-Za-z0-9+/]{1500,}={0,2}")


def scan_malware(text, ext):
    out = []
    lines = text.splitlines()
    m = REVERSE_SHELL.search(text)
    if m and not _ignored(lines[_line_of(text, m.start()) - 1] if lines else ""):
        out.append({"rule": "MAL004", "line": _line_of(text, m.start()),
                    "msg": "Remote-control pattern: %s" % re.sub(r"\s+", " ", m.group(0))[:90]})
    if ext in (".py", ".js", ".bat", ".cmd", ".ps1", ".vbs"):
        for i, ln in enumerate(text.splitlines(), 1):
            if len(ln) < 1500 or _ignored(ln):
                continue
            b = BLOB.search(ln)
            if b and not re.search(r"data:(image|font|audio|video|application/(font|octet))|LOGO|ICON|IMG|IMAGE|PNG|"
                                   r"JPG|SVG|FONT|WOFF|FAVICON", ln[:max(0, b.start())][-120:], re.I):
                out.append({"rule": "MAL002", "line": i,
                            "msg": "A %d-character encoded blob is stored in code." % len(b.group(0))})
                break
    return out


def scan_filename(relpath):
    out = []
    name = os.path.basename(relpath)
    ext = os.path.splitext(name)[1].lower()
    if DOUBLE_EXT.search(name):
        out.append({"rule": "MAL003", "line": 0, "msg": "'%s' looks like a document but is a program." % name})
    elif ext in EXEC_EXT:
        out.append({"rule": "MAL001", "line": 0, "msg": "'%s' is a %s file." % (name, ext)})
    return out
