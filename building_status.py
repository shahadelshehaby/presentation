"""
building_status.py - read-only status page for the Engineering City dashboard.

    GET /building/status   ->  small JSON, answered from a 5-second cache.

An "item" is one file scanned. It can never slow down or break the platform: the answer is cached,
every error is caught (reported inside the JSON) and it only reads.
Edit TEAM below to change the roles or the minutes a person would need by hand per file.
"""
import threading
import time

from flask import jsonify

PLATFORM_NAME = "CodeGuard - Code Security Scanner"
CACHE_SECONDS = 5
ERROR_VISIBLE_MINUTES = 60

# Who would do this work by hand, for ONE file of platform code. Estimates - set them for your site.
TEAM = [
    {"role": "Secure Code Reviewer",
     "description": "Reads every line of the file looking for dangerous patterns (command injection, unsafe paths, "
                    "debug mode, SQL built from text).",
     "automated": True, "manual_minutes_per_item": 6.0},
    {"role": "Secrets Auditor",
     "description": "Searches the file for passwords, NVR logins, tokens and keys written in plain text.",
     "automated": True, "manual_minutes_per_item": 1.5},
    {"role": "Dependency Analyst",
     "description": "Checks the libraries the platform uses against the vulnerability database and pinned versions.",
     "automated": True, "manual_minutes_per_item": 0.5},
    {"role": "Integrity Checker",
     "description": "Compares the file with the approved baseline and looks for malware signs and unexpected programs.",
     "automated": True, "manual_minutes_per_item": 0.5},
    {"role": "AI Security Reviewer",
     "description": "Explains findings in plain English, separates real problems from false alarms and proposes fixes.",
     "automated": True, "manual_minutes_per_item": 2.0},
    {"role": "OT Security Engineer",
     "description": "Reviews each finding, records a remark and decision, and approves or rejects proposed fixes.",
     "automated": False, "manual_minutes_per_item": 1.0},
]

_cache = {"time": 0.0, "data": None}
_lock = threading.Lock()


def _build():
    import ai
    import db
    import engine
    today = time.strftime("%Y-%m-%d")
    hour_ago = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 3600))
    t = db.q("SELECT COALESCE(SUM(items),0) items, COALESCE(SUM(issues),0) issues FROM activity WHERE at>=?",
             (today,), one=True)
    h = db.q("SELECT COALESCE(SUM(items),0) items FROM activity WHERE at>=?", (hour_ago,), one=True)
    pr, ap = engine.progress, ai.progress
    if pr.get("running"):
        status = "working"
        job = {"step": "%s: %s" % (pr.get("platform"), pr.get("step") or "scanning"),
               "items_done": int(pr.get("done") or 0), "items_total": int(pr.get("total") or 0)}
    elif ap.get("running"):
        status = "working"
        job = {"step": ap.get("step") or "AI review", "items_done": int(ap.get("done") or 0),
               "items_total": int(ap.get("total") or 0)}
    else:
        status, job = "idle", None
    err = None
    if pr.get("last_error") and time.time() - pr.get("last_error_at", 0) < ERROR_VISIBLE_MINUTES * 60:
        err = pr["last_error"]
        if status == "idle":
            status = "error"
    return {"platform": PLATFORM_NAME, "status": status, "current_job": job,
            "counters": {"items_today": int(t["items"]), "items_last_hour": int(h["items"]),
                         "issues_today": int(t["issues"])},
            "last_error": err, "team": TEAM}


def status_view():
    with _lock:
        if _cache["data"] is None or time.time() - _cache["time"] > CACHE_SECONDS:
            try:
                _cache["data"] = _build()
            except Exception as e:      # never break the platform
                _cache["data"] = {"platform": PLATFORM_NAME, "status": "error", "current_job": None,
                                  "counters": {"items_today": 0, "items_last_hour": 0, "issues_today": 0},
                                  "last_error": str(e), "team": TEAM}
            _cache["time"] = time.time()
        return jsonify(_cache["data"])


def register(app):
    app.add_url_rule("/building/status", "building_status", status_view)
