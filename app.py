"""
CodeGuard - Code Security Scanner for the Engineering City platforms.   Port 5200.

Start with run.bat (or: python run.py). Everything runs offline on this PC.
"""
import csv
import html
import io
import json
import os
import re
import string
import time

from flask import Flask, Response, jsonify, request, send_from_directory

import ai
import building_status
import db
import deps
import engine
import external
import rules

HERE = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.0"
STATUSES = {"new": "New", "under_review": "Under review", "confirmed": "Confirmed", "false_positive": "False positive",
            "accepted_risk": "Accepted risk", "fixed": "Fixed"}
NEEDS_PIN = ("false_positive", "accepted_risk")
NEEDS_REASON = ("false_positive", "accepted_risk")
SELFTEST_EXPECTED = ["PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007", "PY008", "PY009", "PY010", "PY011",
                     "PY012", "PY014", "PY015", "PY017", "PY020", "BUG002", "BUG003", "BUG004", "BUG005", "BUG006",
                     "BUG009", "BUG010", "JS001", "JS002", "JS003", "JS005", "JS006", "BAT001", "BAT002", "BAT004",
                     "SEC001", "SEC002", "SEC005", "DEP001", "MAL002", "MAL003"]

app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False


class UserError(Exception):
    pass


@app.errorhandler(UserError)
def _user_error(e):
    return jsonify({"ok": False, "error": str(e)}), 400


@app.errorhandler(RuntimeError)
def _runtime_error(e):
    return jsonify({"ok": False, "error": str(e)}), 400


@app.after_request
def _headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def body():
    return request.get_json(silent=True) or {}


def need_by(b):
    by = str(b.get("by") or "").strip()
    if not by:
        raise UserError("Choose who you are (top right) first.")
    return by[:80]


def need_pin(b):
    if not db.check_pin(b.get("pin")):
        raise UserError("Wrong or missing approval PIN.")


def role_of(name):
    for p in db.load_settings().get("people", []):
        if p.get("name") == name:
            return p.get("role", "")
    return ""


def platform_or_404(pid):
    p = db.q("SELECT * FROM platforms WHERE id=?", (pid,), one=True)
    if not p:
        raise UserError("Platform not found.")
    return p


# =============================================================== pages
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# =============================================================== overview
def platform_summaries():
    out = []
    for p in db.q("SELECT * FROM platforms ORDER BY enabled DESC, name"):
        s = db.q("SELECT * FROM scans WHERE id=?", (p["last_scan_id"],), one=True) if p["last_scan_id"] else None
        last_any = db.q("SELECT status, error, started FROM scans WHERE platform_id=? ORDER BY id DESC LIMIT 1",
                        (p["id"],), one=True)
        counts = json.loads(s["counts"]) if s and s["counts"] else {}
        out.append({**p, "exists": os.path.isdir(p["path"]), "score": s["score"] if s else None,
                    "grade": s["grade"] if s else None, "counts": counts, "last_scan": s["finished"] if s else None,
                    "files": s["files"] if s else 0, "lines": s["lines"] if s else 0,
                    "new_findings": s["new_findings"] if s else 0,
                    "last_status": last_any["status"] if last_any else None,
                    "last_error": last_any["error"] if last_any else None,
                    "awaiting": db.q("SELECT COUNT(*) n FROM findings WHERE platform_id=? AND state='open' AND status='new'",
                                     (p["id"],), one=True)["n"],
                    "fixes_waiting": db.q("SELECT COUNT(*) n FROM fixes WHERE platform_id=? AND status='proposed'",
                                          (p["id"],), one=True)["n"]})
    return out


@app.route("/api/state")
def api_state():
    s = db.load_settings()
    plats = platform_summaries()
    active = [p for p in plats if p["enabled"] and p["grade"]]
    worst = sorted(active, key=lambda p: p["score"] or 0)[:1]
    totals = {k: sum(p["counts"].get(k, 0) for p in plats if p["enabled"]) for k in rules.SEVERITIES}
    return jsonify({
        "version": VERSION, "platforms": plats, "totals": totals,
        "progress": engine.progress, "ai_progress": ai.progress, "vulndb": deps.db_info(),
        "tools": external.available(s), "people": s.get("people", []), "pin_set": bool(s.get("approval_pin_hash")),
        "ai_enabled": bool(s.get("ai", {}).get("enabled")), "ai_model": s.get("ai", {}).get("model"),
        "worst": worst[0]["name"] if worst else None,
        "statuses": STATUSES, "layers": rules.LAYERS, "severities": rules.SEVERITIES,
        "nightly": s.get("nightly_scan") if s.get("nightly_enabled") else None})


# =============================================================== platforms + folders
def detect_name(path):
    bs = os.path.join(path, "building_status.py")
    try:
        with open(bs, encoding="utf-8", errors="replace") as fh:
            m = re.search(r'PLATFORM(?:_NAME)?\s*=\s*["\']([^"\']+)', fh.read())
            if m:
                return m.group(1)
    except OSError:
        pass
    return os.path.basename(os.path.normpath(path)).replace("_", " ").title()


def looks_like_platform(path):
    try:
        names = set(os.listdir(path))
    except OSError:
        return False
    return bool(names & {"app.py", "run.bat", "run.py", "building_status.py", "requirements.txt"}) or \
        any(n.endswith(".py") for n in names)


@app.route("/api/browse")
def api_browse():
    path = request.args.get("path", "").strip()
    if not path:
        if os.name == "nt":
            drives = ["%s:\\" % d for d in string.ascii_uppercase if os.path.exists("%s:\\" % d)]
            return jsonify({"path": "", "parent": None, "dirs": [{"name": d, "path": d, "platform": False} for d in drives]})
        path = os.path.expanduser("~")
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        raise UserError("Folder not found: %s" % path)
    dirs = []
    try:
        for n in sorted(os.listdir(path), key=str.lower):
            full = os.path.join(path, n)
            if os.path.isdir(full) and not n.startswith((".", "$")) and n not in ("__pycache__",):
                dirs.append({"name": n, "path": full, "platform": looks_like_platform(full)})
    except PermissionError:
        raise UserError("No permission to open %s" % path)
    parent = os.path.dirname(path.rstrip("\\/")) if os.path.dirname(path.rstrip("\\/")) != path else None
    if os.name == "nt" and len(path) <= 3:
        parent = ""
    return jsonify({"path": path, "parent": parent, "dirs": dirs[:400], "platform": looks_like_platform(path)})


@app.route("/api/discover", methods=["POST"])
def api_discover():
    parent = str(body().get("parent") or "").strip()
    if not os.path.isdir(parent):
        raise UserError("Folder not found: %s" % parent)
    known = {os.path.normcase(os.path.realpath(p["path"])) for p in db.q("SELECT path FROM platforms")}
    found = []
    for n in sorted(os.listdir(parent), key=str.lower):
        full = os.path.join(parent, n)
        if os.path.isdir(full) and looks_like_platform(full):
            found.append({"name": detect_name(full), "path": full,
                          "added": os.path.normcase(os.path.realpath(full)) in known})
    if looks_like_platform(parent) and not found:
        found.append({"name": detect_name(parent), "path": parent,
                      "added": os.path.normcase(os.path.realpath(parent)) in known})
    return jsonify({"found": found})


def _add_platform(name, path, excludes=""):
    path = os.path.abspath(str(path or "").strip().strip('"'))
    if not os.path.isdir(path):
        raise UserError("Folder not found: %s" % path)
    for p in db.q("SELECT * FROM platforms"):
        if os.path.normcase(os.path.realpath(p["path"])) == os.path.normcase(os.path.realpath(path)):
            raise UserError("This folder is already connected as '%s'." % p["name"])
    name = (str(name or "").strip() or detect_name(path))[:80]
    return db.x("INSERT INTO platforms(name, path, enabled, excludes, created) VALUES(?,?,1,?,?)",
                (name, path, str(excludes or "")[:500], db.now()))


@app.route("/api/platforms", methods=["GET", "POST"])
def api_platforms():
    if request.method == "GET":
        return jsonify(platform_summaries())
    b = body()
    items = b.get("items") or [b]
    ids, errors = [], []
    for it in items:
        try:
            ids.append(_add_platform(it.get("name"), it.get("path"), it.get("excludes", "")))
        except UserError as e:
            errors.append(str(e))
    if b.get("scan") and ids:
        for i in ids:
            engine.enqueue_scan(i, "added")
    if not ids and errors:
        raise UserError("; ".join(errors))
    return jsonify({"ok": True, "ids": ids, "errors": errors})


@app.route("/api/platforms/<int:pid>", methods=["PUT", "DELETE"])
def api_platform(pid):
    p = platform_or_404(pid)
    b = body()
    if request.method == "DELETE":
        need_pin(b)
        for t in ("findings", "scans", "file_index", "baseline", "fixes", "components"):
            db.x("DELETE FROM %s WHERE platform_id=?" % t, (pid,))
        db.x("DELETE FROM remarks WHERE finding_id NOT IN (SELECT id FROM findings)")
        db.x("DELETE FROM platforms WHERE id=?", (pid,))
        return jsonify({"ok": True})
    path = str(b.get("path", p["path"])).strip().strip('"')
    if not os.path.isdir(path):
        raise UserError("Folder not found: %s" % path)
    db.x("UPDATE platforms SET name=?, path=?, enabled=?, excludes=? WHERE id=?",
         (str(b.get("name", p["name"]))[:80], os.path.abspath(path), 1 if b.get("enabled", p["enabled"]) else 0,
          str(b.get("excludes", p["excludes"]) or "")[:500], pid))
    return jsonify({"ok": True})


@app.route("/api/platforms/<int:pid>/baseline", methods=["POST"])
def api_baseline(pid):
    b = body()
    by = need_by(b)
    need_pin(b)
    platform_or_404(pid)
    return jsonify({"ok": True, **engine.approve_baseline(pid, by)})


@app.route("/api/files")
def api_files():
    pid = int(request.args.get("platform_id", 0))
    rows = db.q("SELECT file, size FROM file_index WHERE platform_id=? ORDER BY file", (pid,))
    counts = {r["file"]: r["n"] for r in db.q("SELECT file, COUNT(*) n FROM findings WHERE platform_id=? AND state='open' "
                                               "GROUP BY file", (pid,))}
    exts = (".py", ".js", ".html", ".htm", ".bat", ".cmd", ".ps1")
    return jsonify([dict(r, findings=counts.get(r["file"], 0)) for r in rows if r["file"].lower().endswith(exts)])


@app.route("/api/code")
def api_code():
    p = platform_or_404(int(request.args.get("platform_id", 0)))
    rel = request.args.get("file", "")
    line = int(request.args.get("line", 0) or 0)
    radius = min(400, int(request.args.get("radius", 12)))
    start, lines = ai.context(p, rel, line, radius=radius)
    return jsonify({"start": start, "lines": lines, "file": rel})


# =============================================================== scans
@app.route("/api/scan", methods=["POST"])
def api_scan():
    b = body()
    if b.get("all"):
        return jsonify({"ok": True, "queued": engine.scan_all("manual")})
    platform_or_404(int(b.get("platform_id", 0)))
    return jsonify({"ok": True, "queued": 1 if engine.enqueue_scan(int(b["platform_id"]), "manual") else 0})


@app.route("/api/scans")
def api_scans():
    pid = request.args.get("platform_id")
    rows = db.q("SELECT s.*, p.name platform FROM scans s LEFT JOIN platforms p ON p.id=s.platform_id %s "
                "ORDER BY s.id DESC LIMIT 200" % ("WHERE s.platform_id=?" if pid else ""), (int(pid),) if pid else ())
    for r in rows:
        r["counts"] = json.loads(r["counts"] or "{}")
        r["changed_files"] = json.loads(r["changed_files"] or "[]")
        r["notes"] = json.loads(r["notes"] or "[]")
    return jsonify(rows)


# =============================================================== findings
@app.route("/api/findings")
def api_findings():
    a = request.args
    where, args = ["1=1"], []
    if a.get("platform_id"):
        where.append("f.platform_id=?")
        args.append(int(a["platform_id"]))
    state = a.get("state", "open")
    if state in ("open", "resolved"):
        where.append("f.state=?")
        args.append(state)
    for key in ("status", "severity", "layer", "rule"):
        if a.get(key):
            vals = a[key].split(",")
            where.append("f.%s IN (%s)" % (key, ",".join("?" * len(vals))))
            args += vals
    if a.get("scan_id"):
        where.append("f.first_scan_id=?")
        args.append(int(a["scan_id"]))
    if a.get("q"):
        where.append("(f.file LIKE ? OR f.msg LIKE ? OR f.title LIKE ? OR f.code LIKE ?)")
        args += ["%" + a["q"] + "%"] * 4
    if a.get("file"):
        where.append("f.file=?")
        args.append(a["file"])
    rows = db.q("""SELECT f.id, f.platform_id, p.name platform, f.layer, f.rule, f.severity, f.title, f.file, f.line,
                   f.code, f.msg, f.tool, f.source, f.state, f.status, f.status_by, f.first_seen, f.last_seen,
                   (f.ai IS NOT NULL AND f.ai!='') has_ai,
                   (SELECT COUNT(*) FROM remarks r WHERE r.finding_id=f.id AND r.kind='remark') remarks
                   FROM findings f LEFT JOIN platforms p ON p.id=f.platform_id WHERE %s
                   ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                   WHEN 'low' THEN 3 ELSE 4 END, p.name, f.file, f.line LIMIT 3000""" % " AND ".join(where), args)
    return jsonify(rows)


@app.route("/api/findings/<int:fid>")
def api_finding(fid):
    f = db.q("SELECT f.*, p.name platform, p.path FROM findings f LEFT JOIN platforms p ON p.id=f.platform_id "
             "WHERE f.id=?", (fid,), one=True)
    if not f:
        raise UserError("Finding not found")
    f["rule_info"] = rules.rule(f["rule"])
    f["ai"] = json.loads(f["ai"]) if f.get("ai") else None
    f["remarks"] = db.q("SELECT * FROM remarks WHERE finding_id=? ORDER BY id", (fid,))
    f["fixes"] = [ai.fix_view(x["id"]) for x in db.q("SELECT id FROM fixes WHERE finding_id=? ORDER BY id DESC", (fid,))]
    f["context"] = None
    if f["file"] and f["state"] == "open":
        try:
            p = {"path": f["path"], "name": f["platform"], "id": f["platform_id"]}
            start, lines = ai.context(p, f["file"], f["line"], radius=8)
            f["context"] = {"start": start, "lines": lines}
        except Exception as e:
            f["context"] = {"error": str(e)}
    f.pop("path", None)
    return jsonify(f)


def _set_status(fid, b, by):
    status = b.get("status")
    if status not in STATUSES:
        raise UserError("Unknown status")
    remark = str(b.get("remark") or "").strip()
    if status in NEEDS_REASON and not remark:
        raise UserError("Please write the reason in the remark when marking '%s'." % STATUSES[status])
    review_by = str(b.get("review_by") or "").strip()[:10] if status == "accepted_risk" else None
    old = db.q("SELECT status, platform_id FROM findings WHERE id=?", (fid,), one=True)
    if not old:
        raise UserError("Finding not found")
    db.x("UPDATE findings SET status=?, status_by=?, status_at=?, review_by=? WHERE id=?",
         (status, by, db.now(), review_by, fid))
    txt = "Status: %s -> %s." % (STATUSES.get(old["status"], old["status"]), STATUSES[status])
    if review_by:
        txt += " Review again by %s." % review_by
    db.add_remark(fid, by, role_of(by), "status", txt + ((" " + remark) if remark else ""))
    return old["platform_id"]


@app.route("/api/findings/<int:fid>/status", methods=["POST"])
def api_status(fid):
    b = body()
    by = need_by(b)
    if b.get("status") in NEEDS_PIN:
        need_pin(b)
    pid = _set_status(fid, b, by)
    engine.refresh_score(pid)
    return jsonify({"ok": True})


@app.route("/api/findings/bulk_status", methods=["POST"])
def api_bulk_status():
    b = body()
    by = need_by(b)
    if b.get("status") in NEEDS_PIN:
        need_pin(b)
    pids = set()
    for fid in (b.get("ids") or [])[:1000]:
        pids.add(_set_status(int(fid), b, by))
    for pid in pids:
        engine.refresh_score(pid)
    return jsonify({"ok": True, "updated": len(b.get("ids") or [])})


@app.route("/api/findings/<int:fid>/remark", methods=["POST"])
def api_remark(fid):
    b = body()
    by = need_by(b)
    text = str(b.get("text") or "").strip()
    if not text:
        raise UserError("The remark is empty.")
    if not db.q("SELECT id FROM findings WHERE id=?", (fid,), one=True):
        raise UserError("Finding not found")
    db.add_remark(fid, by, role_of(by), "remark", text[:4000])
    if b.get("mark_under_review"):
        f = db.q("SELECT status FROM findings WHERE id=?", (fid,), one=True)
        if f["status"] == "new":
            db.x("UPDATE findings SET status='under_review', status_by=?, status_at=? WHERE id=?", (by, db.now(), fid))
    return jsonify({"ok": True})


# =============================================================== AI reviewer
@app.route("/api/ai/test", methods=["POST"])
def api_ai_test():
    return jsonify(ai.test_connection())


@app.route("/api/ai/explain/<int:fid>", methods=["POST"])
def api_ai_explain(fid):
    return jsonify({"ok": True, "ai": ai.explain(fid)})


@app.route("/api/ai/fix/<int:fid>", methods=["POST"])
def api_ai_fix(fid):
    return jsonify({"ok": True, "fix": ai.propose_fix(fid, need_by(body()))})


@app.route("/api/ai/review_file", methods=["POST"])
def api_ai_review():
    b = body()
    pid, rel = int(b.get("platform_id", 0)), str(b.get("file") or "")
    platform_or_404(pid)
    if not rel:
        raise UserError("Choose a file.")
    ai.submit("AI file review: %s" % rel, lambda: ai.review_file(pid, rel))
    return jsonify({"ok": True})


@app.route("/api/ai/triage", methods=["POST"])
def api_ai_triage():
    pid = int(body().get("platform_id", 0))
    platform_or_404(pid)
    ai.submit("AI triage", lambda: ai.triage_platform(pid, only_new=False))
    return jsonify({"ok": True})


@app.route("/api/fixes")
def api_fixes():
    st = request.args.get("status", "proposed")
    rows = db.q("SELECT x.id FROM fixes x WHERE (?='' OR x.status=?) ORDER BY x.id DESC LIMIT 200", (st, st))
    out = []
    for r in rows:
        fx = ai.fix_view(r["id"])
        f = db.q("SELECT f.title, f.severity, p.name platform FROM findings f LEFT JOIN platforms p ON p.id=f.platform_id "
                 "WHERE f.id=?", (fx["finding_id"],), one=True) or {}
        out.append({**fx, **f})
    return jsonify(out)


@app.route("/api/fixes/<int:fix_id>/<action>", methods=["POST"])
def api_fix_action(fix_id, action):
    b = body()
    by = need_by(b)
    if action == "apply":
        need_pin(b)
        return jsonify(ai.apply_fix(fix_id, by, b.get("proposed")))
    if action == "undo":
        need_pin(b)
        return jsonify(ai.undo_fix(fix_id, by))
    if action == "reject":
        return jsonify(ai.reject_fix(fix_id, by, str(b.get("reason") or "")))
    raise UserError("Unknown action")


# =============================================================== libraries / SBOM
@app.route("/api/components")
def api_components():
    pid = request.args.get("platform_id")
    out = []
    for r in db.q("SELECT c.*, p.name FROM components c JOIN platforms p ON p.id=c.platform_id %s"
                  % ("WHERE c.platform_id=?" if pid else ""), (int(pid),) if pid else ()):
        for comp in json.loads(r["data"]):
            out.append(dict(comp, platform=r["name"], platform_id=r["platform_id"]))
    return jsonify(out)


@app.route("/api/sbom/<int:pid>")
def api_sbom(pid):
    p = platform_or_404(pid)
    r = db.q("SELECT data FROM components WHERE platform_id=?", (pid,), one=True)
    data = deps.sbom(p["name"], json.loads(r["data"]) if r else [])
    fname = "sbom_%s.cdx.json" % "".join(c if c.isalnum() else "_" for c in p["name"])
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=%s" % fname})


# =============================================================== exports & reports
def _csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.route("/api/export.csv")
def api_export():
    pid = request.args.get("platform_id")
    rows = db.q("""SELECT p.name platform, f.severity, f.layer, f.rule, f.title, f.file, f.line, f.msg, f.state, f.status,
                   f.status_by, f.first_seen, f.last_seen,
                   (SELECT r.author || ': ' || r.text FROM remarks r WHERE r.finding_id=f.id AND r.kind IN ('remark','status')
                    ORDER BY r.id DESC LIMIT 1) last_remark
                   FROM findings f JOIN platforms p ON p.id=f.platform_id %s ORDER BY p.name, f.severity"""
                % ("WHERE f.platform_id=?" if pid else ""), (int(pid),) if pid else ())
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["platform", "severity", "layer", "rule", "title", "file", "line", "msg", "state", "status", "status_by",
            "first_seen", "last_seen", "last_remark"]
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_safe(r[c]) for c in cols])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=codeguard_findings_%s.csv" % time.strftime("%Y%m%d")})


@app.route("/report")
def report():
    e = html.escape
    pid = request.args.get("platform_id")
    plats = [p for p in platform_summaries() if (not pid or str(p["id"]) == pid) and p["enabled"]]
    sev_color = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467", "info": "#667085"}
    parts = ["""<!doctype html><html><head><meta charset="utf-8"><title>CodeGuard security report</title><style>
body{font:13px/1.5 Segoe UI,Arial,sans-serif;color:#1d2939;margin:28px;max-width:1100px}
h1{font-size:22px;margin:0}h2{font-size:17px;margin:26px 0 6px;border-bottom:2px solid #1d2939;padding-bottom:3px}
h3{font-size:14px;margin:16px 0 4px}table{border-collapse:collapse;width:100%;margin:6px 0 12px}
th,td{border:1px solid #d0d5dd;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f2f4f7}
.sev{color:#fff;border-radius:3px;padding:0 5px;font-size:11px;text-transform:uppercase}code{font:11px Consolas,monospace;
background:#f2f4f7;padding:1px 3px;word-break:break-all}.grade{font-size:20px;font-weight:700}.muted{color:#667085}
.btn{position:fixed;top:12px;right:12px;padding:8px 14px;background:#1d2939;color:#fff;border:0;border-radius:6px;cursor:pointer}
@media print{.btn{display:none}body{margin:10mm}}</style></head><body>
<button class="btn" onclick="window.print()">Print / Save as PDF</button>"""]
    parts.append("<h1>CodeGuard - code security report</h1><div class='muted'>Generated %s on this PC. Passwords are masked."
                 "</div>" % e(db.now()))
    parts.append("<h2>Summary</h2><table><tr><th>Platform</th><th>Grade</th><th>Score</th><th>Critical</th><th>High</th>"
                 "<th>Medium</th><th>Low</th><th>Files</th><th>Last scan</th></tr>")
    for p in plats:
        c = p["counts"]
        parts.append("<tr><td>%s</td><td class='grade'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                     "<td>%s</td><td>%s</td></tr>" % (e(p["name"]), e(p["grade"] or "-"), e(str(p["score"] or "-")),
                                                     c.get("critical", 0), c.get("high", 0), c.get("medium", 0),
                                                     c.get("low", 0), p["files"], e(p["last_scan"] or "never")))
    parts.append("</table><p class='muted'>Score counts only open findings that are New, Under review or Confirmed. "
                 "False positives and accepted risks are listed separately with the engineer's reason.</p>")
    for p in plats:
        parts.append("<h2>%s</h2><div class='muted'>%s</div>" % (e(p["name"]), e(p["path"])))
        rows = db.q("""SELECT * FROM findings WHERE platform_id=? AND state='open' ORDER BY CASE severity WHEN 'critical'
                       THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, file, line""", (p["id"],))
        groups = [("Open findings", [r for r in rows if r["status"] in ("new", "under_review", "confirmed")]),
                  ("Accepted risks", [r for r in rows if r["status"] == "accepted_risk"]),
                  ("False positives", [r for r in rows if r["status"] == "false_positive"])]
        for title, items in groups:
            parts.append("<h3>%s (%d)</h3>" % (title, len(items)))
            if not items:
                continue
            parts.append("<table><tr><th>Severity</th><th>Problem</th><th>Where</th><th>Status</th><th>Latest remark</th></tr>")
            for r in items:
                rm = db.q("SELECT author, text, created FROM remarks WHERE finding_id=? AND kind IN ('remark','status') "
                          "ORDER BY id DESC LIMIT 1", (r["id"],), one=True)
                parts.append("<tr><td><span class='sev' style='background:%s'>%s</span></td><td><b>%s</b><br>%s</td>"
                             "<td><code>%s:%s</code>%s</td><td>%s%s</td><td>%s</td></tr>" % (
                                 sev_color.get(r["severity"], "#667085"), e(r["severity"]), e(r["title"]), e(r["msg"] or ""),
                                 e(r["file"]), r["line"], ("<br><code>%s</code>" % e(r["code"][:160])) if r["code"] else "",
                                 e(STATUSES.get(r["status"], r["status"])),
                                 (" (review by %s)" % e(r["review_by"])) if r["review_by"] else "",
                                 ("<b>%s</b> %s<br><span class='muted'>%s</span>" % (e(rm["author"]), e(rm["text"]), e(rm["created"])))
                                 if rm else "-"))
            parts.append("</table>")
        comp = db.q("SELECT data FROM components WHERE platform_id=?", (p["id"],), one=True)
        if comp:
            cs = json.loads(comp["data"])
            parts.append("<h3>Libraries (%d)</h3><table><tr><th>Package</th><th>Version</th><th>Declared</th>"
                         "<th>Known vulnerabilities</th></tr>" % len(cs))
            for c in cs:
                parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    e(c["name"]), e(c["version"] or "unknown"), e(c["declared"]), e(", ".join(c.get("vulns", [])) or "-")))
            parts.append("</table>")
    vdb = deps.db_info()
    parts.append("<p class='muted'>Vulnerability database: %s</p></body></html>" % (
        e("%s, %s advisories, built %s" % (vdb["source"], vdb["count"], vdb["built_at"])) if vdb["loaded"]
        else "not installed (libraries were only checked for pinned versions)"))
    return Response("".join(parts), mimetype="text/html")


# =============================================================== settings
@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    s = db.load_settings()
    if request.method == "GET":
        out = {k: v for k, v in s.items() if not k.startswith("approval_pin")}
        out["ai"] = dict(s["ai"], api_key="(set)" if s["ai"].get("api_key") else "")
        return jsonify(out)
    b = body()
    need_pin(b)
    new = b.get("settings") or {}
    for k in ("nightly_scan", "nightly_enabled", "people", "external_tools_enabled", "semgrep_path", "semgrep_rules",
              "gitleaks_path", "clamscan_path", "default_excludes", "max_file_mb", "host", "port"):
        if k in new:
            s[k] = new[k]
    if isinstance(new.get("ai"), dict):
        for k, v in new["ai"].items():
            if k == "api_key" and v == "(set)":
                continue
            s["ai"][k] = v
    s["people"] = [{"name": str(p.get("name", "")).strip()[:80], "role": str(p.get("role", "")).strip()[:80]}
                   for p in s.get("people", []) if str(p.get("name", "")).strip()]
    db.save_settings(s)
    return jsonify({"ok": True})


@app.route("/api/settings/pin", methods=["POST"])
def api_pin():
    b = body()
    if not db.check_pin(b.get("old_pin")):
        raise UserError("The current PIN is wrong.")
    new = str(b.get("new_pin") or "")
    if new and len(new) < 4:
        raise UserError("Use at least 4 characters.")
    db.set_pin(new)
    return jsonify({"ok": True, "pin_set": bool(new)})


@app.route("/api/vulndb/import", methods=["POST"])
def api_vulndb_import():
    up = request.files.get("file")
    if up:
        tmp = os.path.join(db.DATA_DIR, "osv_upload.zip")
        up.save(tmp)
        path = tmp
    else:
        path = str(body().get("path") or "").strip().strip('"')
        if os.path.isdir(path):
            path = os.path.join(path, "PyPI_all.zip") if os.path.isfile(os.path.join(path, "PyPI_all.zip")) else \
                os.path.join(path, "all.zip")
    if not os.path.isfile(path):
        raise UserError("File not found: %s" % path)
    meta = deps.build_db_from_osv_zip(path)
    return jsonify({"ok": True, **meta})


@app.route("/api/selftest", methods=["POST"])
def api_selftest():
    sample = os.path.join(HERE, "selftest_sample")
    p = db.q("SELECT * FROM platforms WHERE path=?", (sample,), one=True)
    pid = p["id"] if p else db.x("INSERT INTO platforms(name, path, enabled, excludes, created) VALUES(?,?,0,'',?)",
                                 ("[Self-test] vulnerable sample", sample, db.now()))
    sid = engine.run_scan(pid, "self-test")
    found = {r["rule"] for r in db.q("SELECT DISTINCT rule FROM findings WHERE platform_id=? AND state='open'", (pid,))}
    results = [{"rule": r, "title": rules.rule(r)["title"], "ok": r in found} for r in SELFTEST_EXPECTED]
    return jsonify({"ok": all(x["ok"] for x in results), "results": results, "scan_id": sid, "platform_id": pid})


# =============================================================== start-up
db.init_db()
building_status.register(app)
engine.start()
