"""
engine.py - runs a scan of one platform folder and keeps the findings up to date.

A finding is identified by a fingerprint (rule + file + the text of the code line), not by its line number,
so remarks and decisions stay attached when code moves up or down. After each scan:
  * new problems           -> added with status "new"
  * problems still there   -> updated (line number, message)
  * problems that are gone -> state "resolved" and status "fixed" (with an automatic remark)
  * a fixed problem that comes back -> reopened for review (with an automatic remark)
Scans run one at a time in a background worker, so the web pages always stay responsive.
"""
import hashlib
import json
import os
import queue
import re
import threading
import time
import traceback

import db
import deps
import external
import rules
import scan_python
import scan_text

HERE = os.path.dirname(os.path.abspath(__file__))
# Files compared with the approved baseline (tamper check): code and programs only. Settings/data/log files change
# during normal use, so they are scanned for passwords but not tracked for changes.
TRACKED_EXT = scan_text.CODE_EXT | scan_text.EXEC_EXT | {".css"}
TEXT_RULE_EXT = scan_text.CODE_EXT | scan_text.CONFIG_EXT | scan_text.DOC_EXT - {".csv"}
OPEN_STATUSES = ("new", "under_review", "confirmed")

progress = {"running": False, "platform": None, "step": "", "done": 0, "total": 0, "scan_id": None,
            "queue": [], "last_error": None, "last_error_at": 0}
_jobs = queue.Queue()
_worker = None
_hooks = {"after_scan": []}


# =============================================================== helpers
def safe_path(root, rel):
    """Join and make sure the result stays inside the platform folder (no ..\\ escapes)."""
    root_r = os.path.realpath(root)
    p = os.path.realpath(os.path.join(root_r, rel))
    a, b = os.path.normcase(p), os.path.normcase(root_r)
    if a != b and not a.startswith(b.rstrip("\\/") + os.sep):
        raise ValueError("path outside the platform folder")
    return p


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mask_text(text):
    """Hide passwords/tokens in code shown on screen, in reports and to the AI."""
    text = scan_text.URL_CRED.sub(lambda m: "%s://%s:%s@" % (m.group(1), m.group(2), scan_text._mask(m.group(3)))
                                  if not scan_text._placeholder(m.group(3)) else m.group(0), text)

    def kv(m):
        if scan_text._placeholder(m.group(4), m.group(1)):
            return m.group(0)
        return m.group(0).replace(m.group(4), scan_text._mask(m.group(4)))
    text = scan_text.KEY_ASSIGN.sub(kv, text)
    for rx, _label in scan_text.TOKENS:
        text = rx.sub(lambda m: scan_text._mask(m.group(0)), text)
    return text


def excludes_for(platform, settings):
    ex = [e.strip() for e in (settings.get("default_excludes") or "").split(",") if e.strip()]
    ex += [e.strip() for e in (platform.get("excludes") or "").split(",") if e.strip()]
    if os.path.realpath(platform["path"]) == os.path.realpath(HERE):
        ex += ["selftest_sample", "vulndb", "codeguard_data", "usb_bundle"]
    return set(e.lower() for e in ex)


def walk(root, excl):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in excl and not d.lower().startswith("codeguard_backup")]
        for fn in filenames:
            ab = os.path.join(dirpath, fn)
            yield os.path.relpath(ab, root).replace("\\", "/"), ab


def read_text(path, max_bytes):
    with open(path, "rb") as fh:
        raw = fh.read(max_bytes + 1)
    if len(raw) > max_bytes or b"\x00" in raw[:8192]:
        return None
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def score_for(findings_rows):
    penalty = 0.0
    counts = {s: 0 for s in rules.SEVERITIES}
    for f in findings_rows:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        penalty += rules.SEVERITY_WEIGHT.get(f["severity"], 0)
    score = round(100.0 * 50.0 / (50.0 + penalty), 1)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"
    if counts.get("critical") and grade in "ABC":
        grade = "D"
    return score, grade, counts


def counting_findings(pid):
    """Open findings that count against the score (false positives and accepted risks do not)."""
    return db.q("SELECT * FROM findings WHERE platform_id=? AND state='open' AND status IN ('new','under_review','confirmed')",
                (pid,))


def refresh_score(pid):
    score, grade, counts = score_for(counting_findings(pid))
    p = db.q("SELECT last_scan_id FROM platforms WHERE id=?", (pid,), one=True)
    if p and p["last_scan_id"]:
        db.x("UPDATE scans SET score=?, grade=?, counts=? WHERE id=?", (score, grade, json.dumps(counts), p["last_scan_id"]))
    return score, grade, counts


# =============================================================== the scan
def _collect(platform, settings, set_step):
    root = platform["path"]
    excl = excludes_for(platform, settings)
    max_bytes = int(float(settings.get("max_file_mb", 3)) * 1024 * 1024)
    raw, file_hashes, py_texts, line_count, files_scanned = [], {}, {}, 0, 0
    entries = list(walk(root, excl))
    progress["total"] = len(entries)
    local_modules = {os.path.splitext(os.path.basename(r))[0] for r, _ in entries if r.endswith(".py")} | \
                    {r.split("/")[0] for r, _ in entries if "/" in r}
    any_auth = False
    for i, (rel, ab) in enumerate(entries):
        progress["done"] = i + 1
        ext = os.path.splitext(rel)[1].lower()
        for f in scan_text.scan_filename(rel):
            raw.append(dict(f, file=rel))
        is_req = os.path.basename(rel).lower().startswith("requirements")
        if ext in TRACKED_EXT or is_req:
            try:
                file_hashes[rel] = (sha256_file(ab), os.path.getsize(ab))
            except OSError:
                continue
        if ext not in TEXT_RULE_EXT:
            continue
        if i % 20 == 0:
            set_step("Reading %s" % rel)
        try:
            text = read_text(ab, max_bytes)
        except OSError:
            text = None
        if text is None:
            continue
        files_scanned += 1
        line_count += text.count("\n") + 1
        found = []
        if ext == ".py":
            py_texts[rel] = text
            found += scan_python.scan(text, rel)
            any_auth = any_auth or scan_python.has_auth(text)
        elif ext in (".js", ".html", ".htm"):
            found += scan_text.scan_web(text)
            any_auth = any_auth or bool(re.search(r"login|password", text, re.I) and re.search(r"/login|signin", text, re.I))
        elif ext in (".bat", ".cmd", ".ps1"):
            found += scan_text.scan_script(text)
        found += scan_text.scan_secrets(text, ext)
        if ext in scan_text.CODE_EXT:
            found += scan_text.scan_malware(text, ext)
        lines = text.splitlines()
        for f in found:
            f["file"] = rel
            ln = f.get("line") or 0
            code = lines[ln - 1] if 0 < ln <= len(lines) else ""
            if f.get("secret"):
                code = code.replace(f["secret"], scan_text._mask(f["secret"]))
            f["code"] = mask_text(code.strip())[:400]
            raw.append(f)
    # project level: network-exposed and no login anywhere
    exposed = [f for f in raw if f["rule"] == "PY007"]
    if exposed and not any_auth:
        e = exposed[0]
        raw.append({"rule": "PY008", "file": e["file"], "line": e["line"], "code": e.get("code", ""),
                    "msg": "The app listens on the network and no sign-in check was found in any file of this platform."})
    return raw, file_hashes, py_texts, line_count, files_scanned, local_modules


def _fingerprint(pid, f, used):
    basis = "%s|%s|%s|%s" % (f["rule"], f.get("file", ""), re.sub(r"\s+", " ", f.get("code", "")).strip(),
                             f.get("key", ""))
    if not f.get("code") and not f.get("key"):
        basis += "|" + f.get("msg", "")
    fp = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:20]
    n = used.get(fp, 0)
    used[fp] = n + 1
    return fp if n == 0 else "%s-%d" % (fp, n)


def run_scan(pid, trigger="manual"):
    settings = db.load_settings()
    platform = db.q("SELECT * FROM platforms WHERE id=?", (pid,), one=True)
    if not platform:
        return None
    sid = db.x("INSERT INTO scans(platform_id, started, status, trigger) VALUES(?,?,?,?)",
               (pid, db.now(), "running", trigger))
    progress.update(running=True, platform=platform["name"], scan_id=sid, done=0, total=0, step="Starting")

    def set_step(s):
        progress["step"] = s

    notes = []
    try:
        root = platform["path"]
        if not os.path.isdir(root):
            raise RuntimeError("Folder not found: %s" % root)
        set_step("Layers 1, 2, 4, 5: reading files")
        raw, hashes, py_texts, nlines, nfiles, local_mods = _collect(platform, settings, set_step)

        set_step("Layer 3: libraries")
        components, dep_f = deps.analyse(root, py_texts, local_mods, excludes_for(platform, settings))
        info = deps.db_info()
        if not info["loaded"]:
            notes.append("Vulnerability database not installed: libraries were checked for pinning only. "
                         "Import it from the USB bundle (Settings > Vulnerability database).")
        for f in dep_f:
            try:
                with open(safe_path(root, f["file"]), encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
                f["code"] = lines[f["line"] - 1].strip() if 0 < f["line"] <= len(lines) else ""
            except (OSError, ValueError):
                f["code"] = ""
            raw.append(f)
        db.x("INSERT OR REPLACE INTO components(platform_id, data, updated) VALUES(?,?,?)",
             (pid, json.dumps(components), db.now()))

        set_step("Layer 5: comparing with the approved baseline")
        base = {r["file"]: r for r in db.q("SELECT * FROM baseline WHERE platform_id=?", (pid,))}
        if not base:
            db.xmany("INSERT OR REPLACE INTO baseline(platform_id, file, sha256, size) VALUES(?,?,?,?)",
                     [(pid, f, h, s) for f, (h, s) in hashes.items()])
            db.x("UPDATE platforms SET baseline_at=?, baseline_by=? WHERE id=?", (db.now(), "first scan (automatic)", pid))
            notes.append("Baseline created automatically from this first scan (%d files)." % len(hashes))
        else:
            for f, (h, _s) in hashes.items():
                if f not in base:
                    raw.append({"rule": "TAMP002", "file": f, "line": 0, "code": "", "key": h, "msg": "New file: %s" % f})
                elif base[f]["sha256"] != h:
                    raw.append({"rule": "TAMP001", "file": f, "line": 0, "code": "", "key": h,
                                "msg": "Content differs from the baseline approved on %s." % (platform.get("baseline_at") or "?")})
            for f in base:
                if f not in hashes:
                    raw.append({"rule": "TAMP003", "file": f, "line": 0, "code": "", "msg": "Missing file: %s" % f})

        set_step("Optional external tools")
        ext_f, ext_notes = external.run_all(root, settings, excludes_for(platform, settings))
        notes += ext_notes
        for f in ext_f:
            f.setdefault("code", "")
            try:
                if f.get("line"):
                    with open(safe_path(root, f["file"]), encoding="utf-8", errors="replace") as fh:
                        lines = fh.read().splitlines()
                    c = lines[f["line"] - 1] if f["line"] <= len(lines) else ""
                    if f.get("secret"):
                        c = c.replace(f["secret"], scan_text._mask(f["secret"]))
                    f["code"] = mask_text(c.strip())[:400]
            except (OSError, ValueError):
                pass
            raw.append(f)

        set_step("Saving results")
        new_count, resolved_count = _store(pid, sid, raw, root)

        prev = {r["file"]: r["sha256"] for r in db.q("SELECT file, sha256 FROM file_index WHERE platform_id=?", (pid,))}
        changed = sorted([f for f, (h, _) in hashes.items() if prev.get(f) != h] +
                         ["(deleted) " + f for f in prev if f not in hashes]) if prev else []
        db.x("DELETE FROM file_index WHERE platform_id=?", (pid,))
        db.xmany("INSERT INTO file_index(platform_id, file, sha256, size) VALUES(?,?,?,?)",
                 [(pid, f, h, s) for f, (h, s) in hashes.items()])

        _expire_accepted(pid)
        score, grade, counts = score_for(counting_findings(pid))
        db.x("""UPDATE scans SET finished=?, status='done', files=?, lines=?, score=?, grade=?, counts=?, new_findings=?,
                resolved=?, changed_files=?, notes=? WHERE id=?""",
             (db.now(), nfiles, nlines, score, grade, json.dumps(counts), new_count, resolved_count,
              json.dumps(changed[:500]), json.dumps(notes), sid))
        db.x("UPDATE platforms SET last_scan_id=? WHERE id=?", (sid, pid))
        db.log_activity("scan", nfiles, new_count)
        for hook in _hooks["after_scan"]:
            try:
                hook(pid, sid)
            except Exception:
                traceback.print_exc()
        return sid
    except Exception as e:
        traceback.print_exc()
        db.x("UPDATE scans SET finished=?, status='error', error=? WHERE id=?", (db.now(), str(e), sid))
        progress.update(last_error="%s: %s" % (platform["name"], e), last_error_at=time.time())
        return sid
    finally:
        progress.update(running=False, step="", done=0, total=0)


def _store(pid, sid, raw, root):
    now = db.now()
    existing = {r["fingerprint"]: r for r in db.q("SELECT * FROM findings WHERE platform_id=? AND source!='ai'", (pid,))}
    used, seen, new_count = {}, set(), 0
    for f in raw:
        meta = rules.rule(f["rule"])
        sev = f.get("severity") or meta["severity"]
        fp = _fingerprint(pid, f, used)
        seen.add(fp)
        title = meta["title"] if f["rule"] != "EXT001" else "%s finding" % f.get("tool", "External tool")
        layer = meta["layer"]
        if fp in existing:
            old = existing[fp]
            db.x("""UPDATE findings SET line=?, code=?, msg=?, severity=?, last_seen=?, last_scan_id=?, state='open'
                    WHERE id=?""", (f.get("line", 0), f.get("code", ""), f.get("msg", ""), sev, now, sid, old["id"]))
            if old["state"] == "resolved":
                db.x("UPDATE findings SET status='under_review', status_by='scanner', status_at=? WHERE id=?", (now, old["id"]))
                db.add_remark(old["id"], "Scanner", "system", "system",
                              "This problem was gone but came back in scan #%d. Please review again." % sid)
        else:
            fid = db.x("""INSERT INTO findings(platform_id, fingerprint, layer, rule, severity, title, file, line, code, msg,
                          tool, source, first_seen, last_seen, first_scan_id, last_scan_id, state, status)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'open', 'new')""",
                       (pid, fp, layer, f["rule"], sev, title, f.get("file", ""), f.get("line", 0), f.get("code", ""),
                        f.get("msg", ""), f.get("tool", ""), "tool" if f.get("tool") else "rule", now, now, sid, sid))
            new_count += 1
            del fid
    resolved = 0
    for fp, old in existing.items():
        if fp not in seen and old["state"] == "open":
            resolved += 1
            new_status = "fixed" if old["status"] in OPEN_STATUSES else old["status"]
            db.x("UPDATE findings SET state='resolved', status=?, status_by=?, status_at=? WHERE id=?",
                 (new_status, "scanner" if new_status != old["status"] else old["status_by"], now, old["id"]))
            db.add_remark(old["id"], "Scanner", "system", "system", "No longer found in scan #%d." % sid)
    # AI findings stay until their code line disappears from the file
    for a in db.q("SELECT * FROM findings WHERE platform_id=? AND source='ai' AND state='open'", (pid,)):
        try:
            with open(safe_path(root, a["file"]), encoding="utf-8", errors="replace") as fh:
                present = re.sub(r"\s+", " ", a["code"] or "").strip() in re.sub(r"\s+", " ", fh.read())
        except (OSError, ValueError):
            present = False
        if not present:
            resolved += 1
            db.x("UPDATE findings SET state='resolved', status=CASE WHEN status IN ('new','under_review','confirmed') "
                 "THEN 'fixed' ELSE status END, status_at=? WHERE id=?", (now, a["id"]))
            db.add_remark(a["id"], "Scanner", "system", "system", "The code line is gone (scan #%d)." % sid)
    return new_count, resolved


def _expire_accepted(pid):
    today = time.strftime("%Y-%m-%d")
    for f in db.q("SELECT id, review_by FROM findings WHERE platform_id=? AND status='accepted_risk' AND state='open' "
                  "AND review_by IS NOT NULL AND review_by!='' AND review_by<?", (pid, today)):
        db.x("UPDATE findings SET status='under_review', status_by='scanner', status_at=? WHERE id=?", (db.now(), f["id"]))
        db.add_remark(f["id"], "Scanner", "system", "system",
                      "The accepted-risk review date (%s) has passed. Please review again." % f["review_by"])


def approve_baseline(pid, by):
    platform = db.q("SELECT * FROM platforms WHERE id=?", (pid,), one=True)
    rows = db.q("SELECT file, sha256, size FROM file_index WHERE platform_id=?", (pid,))
    db.x("DELETE FROM baseline WHERE platform_id=?", (pid,))
    db.xmany("INSERT INTO baseline(platform_id, file, sha256, size) VALUES(?,?,?,?)",
             [(pid, r["file"], r["sha256"], r["size"]) for r in rows])
    db.x("UPDATE platforms SET baseline_at=?, baseline_by=? WHERE id=?", (db.now(), by, pid))
    for f in db.q("SELECT id FROM findings WHERE platform_id=? AND state='open' AND rule IN ('TAMP001','TAMP002','TAMP003')",
                  (pid,)):
        db.x("UPDATE findings SET state='resolved', status='fixed', status_by=?, status_at=? WHERE id=?",
             (by, db.now(), f["id"]))
        db.add_remark(f["id"], by, "", "system", "Change approved: new baseline set.")
    refresh_score(pid)
    return {"files": len(rows), "platform": platform["name"] if platform else ""}


# =============================================================== job queue + nightly schedule
def _loop():
    while True:
        job = _jobs.get()
        try:
            progress["queue"] = [j for j in progress["queue"] if j != job[1]]
            if job[0] == "scan":
                run_scan(job[1], job[2])
            elif job[0] == "call":
                job[2]()
        except Exception:
            traceback.print_exc()


def enqueue_scan(pid, trigger="manual"):
    if pid in progress["queue"]:
        return False
    progress["queue"].append(pid)
    _jobs.put(("scan", pid, trigger))
    return True


def enqueue_call(fn):
    _jobs.put(("call", None, fn))


def scan_all(trigger="manual"):
    n = 0
    for p in db.q("SELECT id FROM platforms WHERE enabled=1 ORDER BY name"):
        n += 1 if enqueue_scan(p["id"], trigger) else 0
    return n


def _scheduler():
    last_run_day = None
    while True:
        try:
            s = db.load_settings()
            hhmm = time.strftime("%H:%M")
            day = time.strftime("%Y-%m-%d")
            if s.get("nightly_enabled") and hhmm == (s.get("nightly_scan") or "") and last_run_day != day:
                last_run_day = day
                scan_all("nightly")
        except Exception:
            traceback.print_exc()
        time.sleep(20)


def start():
    global _worker
    if _worker is None:
        _worker = threading.Thread(target=_loop, daemon=True, name="codeguard-worker")
        _worker.start()
        threading.Thread(target=_scheduler, daemon=True, name="codeguard-schedule").start()
