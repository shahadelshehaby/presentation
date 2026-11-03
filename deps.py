"""
deps.py - libraries (third-party packages) used by a platform.

* Finds what each platform uses: requirements*.txt plus the imports in its .py files.
* Finds the installed version: the platform's own venv if it has one, otherwise this PC's Python.
* Checks every (package, version) against the offline vulnerability database (vulndb/pypi_vulns.json),
  which is built from the public OSV PyPI database by tools/import_vulndb.py (USB update).
* Produces a parts list (SBOM) in CycloneDX 1.5 JSON.
"""
import glob
import json
import os
import re
import sys
import time
import uuid
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
VULNDB_PATH = os.path.join(HERE, "vulndb", "pypi_vulns.json")

IMPORT_TO_DIST = {"cv2": "opencv-python", "PIL": "pillow", "sklearn": "scikit-learn", "yaml": "pyyaml",
                  "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "dotenv": "python-dotenv",
                  "docx": "python-docx", "pptx": "python-pptx", "serial": "pyserial", "usb": "pyusb",
                  "OpenSSL": "pyopenssl", "Crypto": "pycryptodome", "jwt": "pyjwt", "magic": "python-magic",
                  "snap7": "python-snap7", "influxdb_client": "influxdb-client", "win32api": "pywin32",
                  "win32com": "pywin32", "pythoncom": "pywin32", "skimage": "scikit-image", "attr": "attrs",
                  "google": "protobuf", "zmq": "pyzmq", "fitz": "pymupdf", "imageio_ffmpeg": "imageio-ffmpeg",
                  "werkzeug": "werkzeug", "jinja2": "jinja2", "markupsafe": "markupsafe", "pymodbus": "pymodbus",
                  "opcua": "opcua", "asyncua": "asyncua", "paramiko": "paramiko", "smb": "pysmb"}

_FALLBACK_STDLIB = set("""__future__ _thread abc aifc argparse array ast asynchat asyncio asyncore atexit audioop base64
bdb binascii bisect builtins bz2 calendar cgi cgitb chunk cmath cmd code codecs codeop collections colorsys compileall
concurrent configparser contextlib contextvars copy copyreg cProfile crypt csv ctypes curses dataclasses datetime dbm
decimal difflib dis doctest email encodings ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch fractions
ftplib functools gc getopt getpass gettext glob graphlib grp gzip hashlib heapq hmac html http imaplib imghdr imp
importlib inspect io ipaddress itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap marshal math
mimetypes mmap modulefinder msilib msvcrt multiprocessing netrc nntplib ntpath numbers operator optparse os ossaudiodev
pathlib pdb pickle pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint profile pstats pty pwd
py_compile pyclbr pydoc queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select
selectors shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver sqlite3 ssl stat statistics string
stringprep struct subprocess sunau symtable sys sysconfig syslog tabnanny tarfile telnetlib tempfile termios textwrap
threading time timeit tkinter token tokenize tomllib trace traceback tracemalloc tty turtle types typing unicodedata
unittest urllib uu uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp
zipfile zipimport zlib zoneinfo""".split())
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | _FALLBACK_STDLIB


def norm(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower().strip()


# =============================================================== versions (PEP 440, simplified)
_VRX = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?"
                  r"(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?", re.I)


def vkey(v):
    m = _VRX.match(str(v).strip())
    if not m:
        return ((0,), (0,), (0,), (0,))
    rel = [int(x) for x in m.group(1).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre_map = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
    if m.group(2):
        pre = (pre_map[m.group(2).lower()], int(m.group(3) or 0))
    elif m.group(6) and not m.group(4):
        pre = (-1, 0)                       # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (9, 0)                        # final release
    post = (int(m.group(5) or 0),) if m.group(4) else (-1,)
    dev = (int(m.group(7) or 0),) if m.group(6) else (10 ** 9,)
    return (tuple(rel), pre, post, dev)


def vcmp(a, b):
    ka, kb = vkey(a), vkey(b)
    ra, rb = list(ka[0]), list(kb[0])
    n = max(len(ra), len(rb))
    ra += [0] * (n - len(ra))
    rb += [0] * (n - len(rb))
    ka = (tuple(ra),) + ka[1:]
    kb = (tuple(rb),) + kb[1:]
    return (ka > kb) - (ka < kb)


# =============================================================== what does a platform use?
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def read_requirements(root, excluded=()):
    """-> list of {name, spec, pinned, version, file, line}"""
    out = []
    files = glob.glob(os.path.join(root, "requirements*.txt")) + \
        [f for f in glob.glob(os.path.join(root, "*", "requirements*.txt"))
         if os.path.basename(os.path.dirname(f)).lower() not in excluded]
    for f in files:
        rel = os.path.relpath(f, root)
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines, 1):
            s = ln.split("#", 1)[0].strip()
            if not s or s.startswith("-"):
                continue
            s = s.split(";", 1)[0].strip()
            m = REQ_LINE.match(s)
            if not m:
                continue
            spec = m.group(3).strip()
            pin = re.match(r"^===?\s*([^\s,]+)$", spec)
            out.append({"name": norm(m.group(1)), "display": m.group(1), "spec": spec, "pinned": bool(pin),
                        "version": pin.group(1) if pin else None, "file": rel, "line": i})
    return out


def imported_packages(py_texts, local_modules):
    """Top-level third-party imports in the platform's .py files -> {dist_name: (file, line)}"""
    found = {}
    rx = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))", re.M)
    for rel, text in py_texts.items():
        for m in rx.finditer(text):
            mods = [m.group(1)] if m.group(1) else [x.strip().split(" ")[0] for x in m.group(2).split(",")]
            for mod in mods:
                top = mod.split(".")[0]
                if not top or top in STDLIB or top in local_modules or top.startswith("_"):
                    continue
                dist = norm(IMPORT_TO_DIST.get(top, top))
                found.setdefault(dist, (rel, text.count("\n", 0, m.start()) + 1))
    return found


def installed_versions(root):
    """Installed distributions: the platform's venv if present, else this Python."""
    pats = [os.path.join(root, d, "Lib", "site-packages") for d in ("venv", ".venv", "env", ".env")] + \
           glob.glob(os.path.join(root, "*venv*", "lib", "python*", "site-packages"))
    for sp in pats:
        if os.path.isdir(sp):
            res = {}
            for d in glob.glob(os.path.join(sp, "*.dist-info")):
                m = re.match(r"^(.+?)-([^-]+)\.dist-info$", os.path.basename(d))
                if m:
                    res[norm(m.group(1))] = m.group(2)
            return res, "venv: " + os.path.relpath(sp, root)
    res = {}
    try:
        from importlib import metadata
        for dist in metadata.distributions():
            try:
                res[norm(dist.metadata["Name"])] = dist.version
            except Exception:  # codeguard: ignore - a broken package entry is skipped on purpose
                pass
    except Exception:  # codeguard: ignore - no package metadata available: report versions as unknown
        pass
    return res, "this PC's Python (%s)" % sys.version.split()[0]


# =============================================================== vulnerability database
_DB = {"mtime": None, "data": None}


def load_db():
    try:
        mt = os.path.getmtime(VULNDB_PATH)
    except OSError:
        return None
    if _DB["mtime"] != mt:
        with open(VULNDB_PATH, encoding="utf-8") as fh:
            _DB["data"] = json.load(fh)
        _DB["mtime"] = mt
    return _DB["data"]


def db_info():
    d = load_db()
    if not d:
        return {"loaded": False, "count": 0, "built_at": None, "packages": 0, "source": None}
    meta = d.get("meta", {})
    return {"loaded": True, "count": meta.get("count", 0), "built_at": meta.get("built_at"),
            "packages": len(d.get("packages", {})), "source": meta.get("source")}


def _severity(osv):
    ds = (osv.get("database_specific") or {}).get("severity")
    if isinstance(ds, str):
        s = ds.lower()
        return {"moderate": "medium"}.get(s, s) if s in ("low", "moderate", "medium", "high", "critical") else "medium"
    for s in osv.get("severity") or []:
        score = str(s.get("score", ""))
        m = re.match(r"^\d+(\.\d+)?$", score)
        if m:
            v = float(score)
            return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    return "medium"


def compact_osv(osv):
    """One OSV advisory -> [(package, compact entry)] for PyPI packages."""
    out = []
    for aff in osv.get("affected") or []:
        pkg = aff.get("package") or {}
        if str(pkg.get("ecosystem", "")).lower() != "pypi":
            continue
        ranges, fixed = [], []
        for r in aff.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            intro = None
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev and intro is not None:
                    ranges.append([intro, ev["fixed"], False])
                    fixed.append(ev["fixed"])
                    intro = None
                elif "last_affected" in ev and intro is not None:
                    ranges.append([intro, ev["last_affected"], True])
                    intro = None
            if intro is not None:
                ranges.append([intro, None, False])
        out.append((norm(pkg.get("name", "")), {
            "id": osv.get("id"), "aliases": (osv.get("aliases") or [])[:6],
            "summary": (osv.get("summary") or osv.get("details") or "")[:300],
            "severity": _severity(osv), "ranges": ranges, "versions": (aff.get("versions") or [])[:400],
            "fixed": sorted(set(fixed), key=vkey)}))
    return out


def build_db_from_osv_zip(zip_path, out_path=VULNDB_PATH):
    """Turn OSV's PyPI all.zip (downloaded on an internet PC) into the compact offline database."""
    packages, count, skipped = {}, 0, 0
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            try:
                osv = json.loads(z.read(name).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, KeyError):
                skipped += 1           # a damaged advisory file is skipped, the rest is still imported
                continue
            if osv.get("withdrawn"):
                continue
            for pkg, entry in compact_osv(osv):
                packages.setdefault(pkg, []).append(entry)
                count += 1
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    data = {"meta": {"source": "OSV PyPI (%s)" % os.path.basename(zip_path), "count": count, "skipped": skipped,
                     "built_at": time.strftime("%Y-%m-%d %H:%M")}, "packages": packages}
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    os.replace(tmp, out_path)
    _DB["mtime"] = None
    return data["meta"]


def is_affected(version, entry):
    if version in entry.get("versions", []):
        return True
    for intro, end, inclusive in entry.get("ranges", []):
        lo_ok = intro in ("0", "", None) or vcmp(version, intro) >= 0
        if end is None:
            hi_ok = True
        else:
            c = vcmp(version, end)
            hi_ok = c <= 0 if inclusive else c < 0
        if lo_ok and hi_ok:
            return True
    return False


def vulns_for(name, version):
    d = load_db()
    if not d or not version:
        return []
    return [e for e in d.get("packages", {}).get(norm(name), []) if is_affected(version, e)]


# =============================================================== platform analysis
def analyse(root, py_texts, local_modules, excluded=()):
    """-> (components, findings). Findings use the same shape as the other scanners plus 'file'."""
    reqs = read_requirements(root, excluded)
    imports = imported_packages(py_texts, local_modules)
    installed, source = installed_versions(root)
    comps, findings = {}, []
    for r in reqs:
        comps[r["name"]] = {"name": r["display"], "key": r["name"], "version": r["version"] or installed.get(r["name"]),
                            "declared": r["spec"] or "(any version)", "where": "%s:%d" % (r["file"], r["line"]),
                            "file": r["file"], "line": r["line"], "pinned": r["pinned"], "installed_from": source}
    for dist, (rel, line) in imports.items():
        if dist not in comps:
            comps[dist] = {"name": dist, "key": dist, "version": installed.get(dist), "declared": "(not in requirements)",
                           "where": "%s:%d" % (rel, line), "file": rel, "line": line, "pinned": False,
                           "installed_from": source}
    # unpinned requirements, one finding per requirements file
    by_file = {}
    for r in reqs:
        if not r["pinned"]:
            by_file.setdefault(r["file"], []).append(r)
    for f, rs in by_file.items():
        findings.append({"rule": "DEP001", "file": f, "line": rs[0]["line"],
                         "msg": "%d package(s) without an exact version: %s." % (len(rs), ", ".join(x["display"] for x in rs[:12]))})
    # known vulnerabilities
    for c in comps.values():
        c["vulns"] = []
        for v in vulns_for(c["key"], c["version"]):
            c["vulns"].append(v["id"])
            fix = (" Fixed in %s." % ", ".join(v["fixed"][:3])) if v.get("fixed") else " No fixed version listed."
            findings.append({"rule": "DEP002", "file": c["file"], "line": c["line"], "severity": v["severity"],
                             "msg": "%s %s: %s %s%s" % (c["name"], c["version"], v["id"],
                                                         ("(" + ", ".join(v["aliases"][:2]) + ") ") if v["aliases"] else "",
                                                         (v["summary"][:160] + ".") if v["summary"] else "") + fix,
                             "key": "%s|%s" % (c["key"], v["id"])})
    return sorted(comps.values(), key=lambda c: c["key"]), findings


def sbom(platform_name, components):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:%s" % uuid.uuid4(), "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "tools": [{"vendor": "CodeGuard", "name": "CodeGuard Code Security Scanner"}],
                     "component": {"type": "application", "name": platform_name}},
        "components": [{"type": "library", "name": c["name"], "version": c["version"] or "unknown",
                        "purl": "pkg:pypi/%s@%s" % (c["key"], c["version"] or "unknown"),
                        "properties": [{"name": "codeguard:declared", "value": c["declared"]},
                                       {"name": "codeguard:known_vulnerabilities", "value": ",".join(c.get("vulns", []))}]}
                       for c in components]}
