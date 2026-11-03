"""
db.py - storage for CodeGuard (one SQLite file: codeguard_data/codeguard.db) and settings (settings.json).

Passwords found in scanned files are never stored: the code line kept for each finding is masked first.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "codeguard_data")
DB_PATH = os.path.join(DATA_DIR, "codeguard.db")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS platforms(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL, enabled INTEGER DEFAULT 1,
  excludes TEXT DEFAULT '', created TEXT, last_scan_id INTEGER, baseline_at TEXT, baseline_by TEXT);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, platform_id INTEGER, started TEXT, finished TEXT, status TEXT,
  trigger TEXT, files INTEGER DEFAULT 0, lines INTEGER DEFAULT 0, score REAL, grade TEXT, counts TEXT,
  new_findings INTEGER DEFAULT 0, resolved INTEGER DEFAULT 0, changed_files TEXT, notes TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, platform_id INTEGER, fingerprint TEXT, layer TEXT, rule TEXT,
  severity TEXT, title TEXT, file TEXT, line INTEGER, code TEXT, msg TEXT, tool TEXT, source TEXT DEFAULT 'rule',
  first_seen TEXT, last_seen TEXT, first_scan_id INTEGER, last_scan_id INTEGER, state TEXT DEFAULT 'open',
  status TEXT DEFAULT 'new', status_by TEXT, status_at TEXT, review_by TEXT, ai TEXT,
  UNIQUE(platform_id, fingerprint));
CREATE INDEX IF NOT EXISTS ix_f_platform ON findings(platform_id, state);
CREATE TABLE IF NOT EXISTS remarks(
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER, author TEXT, role TEXT, kind TEXT, text TEXT, created TEXT);
CREATE INDEX IF NOT EXISTS ix_r_finding ON remarks(finding_id);
CREATE TABLE IF NOT EXISTS file_index(
  platform_id INTEGER, file TEXT, sha256 TEXT, size INTEGER, PRIMARY KEY(platform_id, file));
CREATE TABLE IF NOT EXISTS baseline(
  platform_id INTEGER, file TEXT, sha256 TEXT, size INTEGER, PRIMARY KEY(platform_id, file));
CREATE TABLE IF NOT EXISTS fixes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER, platform_id INTEGER, file TEXT, start_line INTEGER,
  end_line INTEGER, original TEXT, proposed TEXT, explanation TEXT, status TEXT DEFAULT 'proposed', created TEXT,
  created_by TEXT, decided_by TEXT, decided_at TEXT, backup_path TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS components(
  platform_id INTEGER, data TEXT, updated TEXT, PRIMARY KEY(platform_id));
CREATE TABLE IF NOT EXISTS activity(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, kind TEXT, items INTEGER, issues INTEGER);
"""

DEFAULT_SETTINGS = {
    "host": "127.0.0.1",
    "port": 5200,
    "nightly_scan": "02:30",
    "nightly_enabled": True,
    "people": [{"name": "OT Security Engineer", "role": "OT Security Engineer"}],
    "approval_pin_hash": "",
    "approval_pin_salt": "",
    "ai": {"enabled": False, "base_url": "http://127.0.0.1:11434/v1", "model": "gpt-oss:20b",
           "api_key": "", "timeout": 240, "max_context_lines": 60, "temperature": 0.1,
           "auto_triage_after_scan": False},
    "external_tools_enabled": True,
    "semgrep_path": "", "semgrep_rules": "", "gitleaks_path": "", "clamscan_path": "",
    "default_excludes": "__pycache__, .git, venv, .venv, env, node_modules, backups, codeguard_data, .idea, .vscode",
    "max_file_mb": 3,
}


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def q(sql, args=(), one=False):
    with _lock, _conn() as c:
        cur = c.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()]
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    with _lock, _conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def xmany(sql, rows):
    with _lock, _conn() as c:
        c.executemany(sql, rows)


# =============================================================== settings
def _merge(base, extra):
    out = json.loads(json.dumps(base))
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as fh:
            return _merge(DEFAULT_SETTINGS, json.load(fh))
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT_SETTINGS))


def save_settings(s):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(s, fh, indent=2)
    os.replace(tmp, SETTINGS_PATH)


def set_pin(pin):
    s = load_settings()
    if not pin:
        s["approval_pin_hash"], s["approval_pin_salt"] = "", ""
    else:
        salt = secrets.token_hex(16)
        s["approval_pin_salt"] = salt
        s["approval_pin_hash"] = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200000).hex()
    save_settings(s)


def check_pin(pin):
    s = load_settings()
    if not s.get("approval_pin_hash"):
        return True
    h = hashlib.pbkdf2_hmac("sha256", str(pin or "").encode(), s["approval_pin_salt"].encode(), 200000).hex()
    return secrets.compare_digest(h, s["approval_pin_hash"])


# =============================================================== remarks / activity
def add_remark(finding_id, author, role, kind, text):
    return x("INSERT INTO remarks(finding_id, author, role, kind, text, created) VALUES(?,?,?,?,?,?)",
             (finding_id, author or "", role or "", kind, text, now()))


def log_activity(kind, items, issues):
    x("INSERT INTO activity(at, kind, items, issues) VALUES(?,?,?,?)", (now(), kind, items, issues))
