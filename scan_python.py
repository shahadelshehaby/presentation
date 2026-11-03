"""
scan_python.py - checks for .py files (security rules + bugs & quality).

The file is parsed into its real structure (Python's own `ast` module), so the checks understand the code
instead of only matching text. Nothing is ever executed.

scan(text) -> list of {"rule", "line", "msg", optional "severity"}
A line containing  "# codeguard: ignore"  or  "# nosec"  is skipped.
"""
import ast
import builtins
import re

SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
FILE_SINKS = {"open", "io.open", "flask.send_file", "send_file", "os.remove", "os.unlink", "os.rmdir",
              "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "os.rename",
              "os.replace", "pathlib.Path", "Path", "os.listdir", "os.scandir"}
HTTP_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
              "requests.patch", "requests.request", "requests.options"}
EXECUTE_ATTRS = {"execute", "executemany", "executescript", "read_sql", "read_sql_query"}
ROUTE_DECOS = {"route", "get", "post", "put", "delete", "patch"}
BUILTIN_NAMES = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__builtins__", "__spec__", "__loader__", "__package__", "__path__",
    "__annotations__", "__dict__", "__class__", "__debug__", "WindowsError", "__version__", "__all__"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def _ignored(lines, lineno):
    if 1 <= lineno <= len(lines):
        s = lines[lineno - 1]
        return "codeguard: ignore" in s or "# nosec" in s
    return False


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_dynamic_str(node):
    """True for f-strings, 'a' + b, 'a %s' % b, 'a{}'.format(b)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)):
        return True
    return False


class _Scanner(ast.NodeVisitor):
    def __init__(self, text):
        self.text = text
        self.lines = text.splitlines()
        self.out = []
        self.aliases = {}          # local name -> full dotted module/function name
        self.tainted = set()       # names holding data that came from the web request
        self.dyn_sql = set()       # names holding dynamically built strings
        self.func_stack = []

    # ----------------------------------------------------------- helpers
    def add(self, rule, node_or_line, msg, severity=None):
        line = node_or_line if isinstance(node_or_line, int) else getattr(node_or_line, "lineno", 1)
        if _ignored(self.lines, line):
            return
        f = {"rule": rule, "line": line, "msg": msg}
        if severity:
            f["severity"] = severity
        self.out.append(f)

    def dotted(self, node):
        """Full dotted name for a call target, resolving import aliases: sp.run -> subprocess.run."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        else:
            return ""
        return ".".join(reversed(parts))

    def is_tainted(self, node):
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and (n.id in self.tainted or n.id == "request"):
                return True
            if isinstance(n, ast.Attribute) and n.attr in ("args", "form", "values", "files", "json") and \
                    isinstance(n.value, ast.Name) and n.value.id == "request":
                return True
        return False

    # ----------------------------------------------------------- imports
    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            if a.name != "*":
                self.aliases[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
        self.generic_visit(node)

    # ----------------------------------------------------------- functions (track request data)
    def visit_FunctionDef(self, node):
        saved_t, saved_d = set(self.tainted), set(self.dyn_sql)
        is_route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECOS
                       for d in node.decorator_list)
        if is_route:      # URL parts like /clip/<name> arrive as function parameters
            for a in node.args.args + node.args.kwonlyargs:
                self.tainted.add(a.arg)
        # mutable default arguments
        for d in node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                    isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "dict", "set")):
                self.add("BUG006", d, "Function '%s' uses a list/dict/set as a default argument." % node.name)
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()
        self.tainted, self.dyn_sql = saved_t, saved_d

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        self._track_assign(node.targets, node.value)
        # secret key in code
        for t in node.targets:
            tname = ""
            if isinstance(t, ast.Attribute):
                tname = t.attr
            elif isinstance(t, ast.Subscript):
                tname = str(_const(t.slice) or "")
            elif isinstance(t, ast.Name):
                tname = t.id
            if tname.lower() in ("secret_key",) and isinstance(_const(node.value), str) and _const(node.value):
                self.add("PY015", node, "The Flask secret key is written in the code.")
            if isinstance(t, ast.Attribute) and t.attr == "debug" and _const(node.value) is True:
                self.add("PY006", node, "app.debug = True switches on the debug console.")
            if isinstance(t, ast.Subscript) and _const(t.slice) == "DEBUG" and _const(node.value) is True:
                self.add("PY006", node, "config['DEBUG'] = True switches on the debug console.")
            if isinstance(t, ast.Name) and "HOST" in t.id.upper() and _const(node.value) in ("0.0.0.0", "::"):
                self.add("PY007", node, "%s = '%s' makes the platform reachable from the whole network."
                         % (t.id, _const(node.value)))
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._track_assign([node.target], node.value)
        self.generic_visit(node)

    def _track_assign(self, targets, value):
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        tainted = self.is_tainted(value)
        dyn = _is_dynamic_str(value)
        for n in names:
            if tainted:
                self.tainted.add(n)
            else:
                self.tainted.discard(n)
            if dyn:
                self.dyn_sql.add(n)
            else:
                self.dyn_sql.discard(n)

    # ----------------------------------------------------------- calls
    def visit_Call(self, node):
        name = self.dotted(node.func)
        short = name.split(".")[-1] if name else ""
        mod = name.split(".")[0] if name else ""

        # PY001 / PY014 subprocess
        if mod == "subprocess" and short in SUBPROCESS_FUNCS:
            shell = _kw(node, "shell")
            args_tainted = any(self.is_tainted(a) for a in node.args) or any(
                self.is_tainted(k.value) for k in node.keywords if k.arg in ("args",))
            if shell is not None and _const(shell) is True:
                first = node.args[0] if node.args else None
                built = first is not None and (_is_dynamic_str(first) or
                                               (isinstance(first, ast.Name) and first.id in self.dyn_sql))
                sev = "critical" if (args_tainted or built) else None
                why = " The command is built from web request data." if args_tainted else (
                    " The command is built from text pieces." if built else "")
                self.add("PY001", node, "%s(..., shell=True).%s" % (name, why), sev)
            elif args_tainted:
                self.add("PY014", node, "%s(...) receives a value that came from the web request." % name)
        # PY002
        if name in ("os.system", "os.popen", "os.popen2", "os.popen3", "commands.getoutput"):
            sev = "critical" if any(self.is_tainted(a) for a in node.args) else None
            self.add("PY002", node, "%s(...) runs the command through the shell." % name, sev)
        # PY003
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec") and node.func.id not in self.aliases:
            sev = "critical" if any(self.is_tainted(a) for a in node.args) else None
            self.add("PY003", node, "%s() runs text as Python code." % node.func.id, sev)
            if node.args and isinstance(node.args[0], ast.Call):
                inner = self.dotted(node.args[0].func)
                if any(x in inner for x in ("b64decode", "decompress", "fromhex", "unhexlify", "decode")):
                    self.add("MAL002", node, "Code is decoded and executed in one step (%s inside %s)."
                             % (inner, node.func.id))
        # PY004
        if name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "marshal.load", "marshal.loads",
                    "dill.load", "dill.loads", "pandas.read_pickle", "pd.read_pickle", "shelve.open"):
            self.add("PY004", node, "%s(...) can run code hidden in the data file." % name)
        # PY005
        if name == "yaml.load":
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            lname = self.dotted(loader).split(".")[-1] if loader is not None else ""
            if lname not in SAFE_YAML_LOADERS:
                self.add("PY005", node, "yaml.load without SafeLoader.")
        if name in ("yaml.unsafe_load", "yaml.full_load"):
            self.add("PY005", node, "%s can build unsafe objects." % name)
        # PY006 / PY007 app.run
        if short == "run" and isinstance(node.func, ast.Attribute) and mod not in ("subprocess", "asyncio"):
            if _const(_kw(node, "debug")) is True:
                self.add("PY006", node, "%s(debug=True)." % (name or "app.run"))
            host = _const(_kw(node, "host"))
            if host in ("0.0.0.0", "::"):
                self.add("PY007", node, "The web app listens on %s (all network addresses)." % host)
        # PY009 SQL
        if isinstance(node.func, ast.Attribute) and node.func.attr in EXECUTE_ATTRS and node.args:
            q = node.args[0]
            if _is_dynamic_str(q) or (isinstance(q, ast.Name) and q.id in self.dyn_sql):
                sev = "critical" if self.is_tainted(q) else None
                self.add("PY009", node, ".%s(...) receives a query built from text pieces." % node.func.attr, sev)
        # PY010 file paths from the request
        if name in FILE_SINKS or (isinstance(node.func, ast.Name) and node.func.id in ("open", "send_file")):
            if node.args and self.is_tainted(node.args[0]):
                self.add("PY010", node, "%s(...) uses a path that came from the web request." % (name or "open"))
        # PY011
        if _const(_kw(node, "verify")) is False:
            self.add("PY011", node, "%s(..., verify=False)." % (name or "call"))
        if name in ("ssl._create_unverified_context",):
            self.add("PY011", node, "ssl._create_unverified_context() disables certificate checks.")
        # PY012
        if name in ("hashlib.md5", "hashlib.sha1") and _const(_kw(node, "usedforsecurity")) is not False:
            self.add("PY012", node, "%s used." % name)
        if name == "hashlib.new" and node.args and str(_const(node.args[0])).lower() in ("md5", "sha1"):
            self.add("PY012", node, "hashlib.new('%s') used." % _const(node.args[0]))
        # PY013
        if name == "tempfile.mktemp":
            self.add("PY013", node, "tempfile.mktemp() used.")
        # PY016
        if short == "extractall" and isinstance(node.func, ast.Attribute):
            self.add("PY016", node, "Archive .extractall() without checking member names.")
        # PY017
        if short == "save" and isinstance(node.func, ast.Attribute) and node.args:
            seg = node.args[0]
            has_filename = any(isinstance(n, ast.Attribute) and n.attr == "filename" for n in ast.walk(seg))
            secured = any(isinstance(n, ast.Call) and self.dotted(n.func).endswith("secure_filename")
                          for n in ast.walk(seg))
            if has_filename and not secured:
                self.add("PY017", node, "Upload saved using file.filename without secure_filename().")
        # PY018
        if name in ("xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.dom.minidom.parse",
                    "xml.dom.minidom.parseString", "xml.sax.parse", "xml.etree.cElementTree.parse"):
            self.add("PY018", node, "%s(...) on XML data." % name)
        # PY020 timeouts
        if name in HTTP_FUNCS and _kw(node, "timeout") is None:
            self.add("PY020", node, "%s(...) has no timeout." % name)
        if name == "urllib.request.urlopen" and _kw(node, "timeout") is None and len(node.args) < 3:
            self.add("PY020", node, "urlopen(...) has no timeout.")
        # BUG007 open() without encoding  (collected, reported once per file)
        if (isinstance(node.func, ast.Name) and node.func.id == "open" and "open" not in self.aliases) or name == "io.open":
            mode = _const(_kw(node, "mode")) if _kw(node, "mode") is not None else (
                _const(node.args[1]) if len(node.args) > 1 else "r")
            if isinstance(mode, str) and "b" not in mode and _kw(node, "encoding") is None and \
                    not _ignored(self.lines, node.lineno):
                self.no_encoding.append(node.lineno)
        self.generic_visit(node)

    # ----------------------------------------------------------- misc checks
    def visit_Compare(self, node):
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant) and \
                    comp.value not in (None, True, False, Ellipsis):
                self.add("BUG009", node, "'is' compared with the literal %r." % (comp.value,))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        body_trivial = all(isinstance(s, (ast.Pass, ast.Continue)) or
                           (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body)
        broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
        if body_trivial and broad:
            self.add("BUG005", node, "Every error in the try block is silently ignored.")
        self.generic_visit(node)


def _check_blocks(tree, sc):
    """Duplicate definitions, duplicate routes, unreachable code."""
    routes = {}
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            body = getattr(node, field, None)
            if not isinstance(body, list):
                continue
            # unreachable code
            for i, st in enumerate(body[:-1]):
                if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    sc.add("BUG010", body[i + 1], "This line follows a %s and never runs." % type(st).__name__.lower())
                    break
            # duplicate defs in the same body (module or class level, or inside one function)
            if field == "body" and isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                seen = {}
                for st in body:
                    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        decos = [sc.dotted(d.func if isinstance(d, ast.Call) else d) for d in st.decorator_list]
                        if any(d.endswith(("setter", "getter", "deleter", "overload", "register")) for d in decos):
                            continue
                        if st.name in seen:
                            sc.add("BUG004", st, "'%s' is defined again here (first at line %d); the first version is "
                                                 "replaced." % (st.name, seen[st.name]))
                        else:
                            seen[st.name] = st.lineno
        # duplicate routes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECOS \
                        and d.args and isinstance(_const(d.args[0]), str):
                    obj = sc.dotted(d.func.value)
                    path = _const(d.args[0])
                    if d.func.attr == "route":
                        m = _kw(d, "methods")
                        methods = [_const(e) for e in m.elts] if isinstance(m, (ast.List, ast.Tuple)) else ["GET"]
                    else:
                        methods = [d.func.attr.upper()]
                    for meth in methods:
                        key = (obj, path, str(meth).upper())
                        if key in routes:
                            sc.add("BUG003", node, "%s %s is already handled by '%s' (line %d); '%s' never runs."
                                   % (key[2], path, routes[key][0], routes[key][1], node.name))
                        else:
                            routes[key] = (node.name, node.lineno)


def _check_names(tree, sc):
    """Undefined names and unused imports (lenient: whole-file view, no scoping)."""
    bound, loaded, imports = set(), {}, {}
    star_import = False
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Load):
                loaded.setdefault(n.id, n.lineno)
            else:
                bound.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, ast.Import):
            for a in n.names:
                nm = a.asname or a.name.split(".")[0]
                bound.add(nm)
                imports.setdefault(nm, n.lineno)
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name == "*":
                    star_import = True
                else:
                    nm = a.asname or a.name
                    bound.add(nm)
                    if n.module != "__future__":
                        imports.setdefault(nm, n.lineno)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound.update(n.names)
        elif type(n).__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None):
            bound.add(n.name)
        elif type(n).__name__ == "MatchMapping" and getattr(n, "rest", None):
            bound.add(n.rest)
    # names referenced only inside strings in __all__ count as used
    text_all = set(re.findall(r"['\"](\w+)['\"]", " ".join(
        sc.lines[i] for i in range(len(sc.lines)) if "__all__" in sc.lines[i])))
    if not star_import:
        for name, line in sorted(loaded.items(), key=lambda x: x[1]):
            if name not in bound and name not in BUILTIN_NAMES:
                sc.add("BUG002", line, "'%s' is used but never defined or imported." % name)
    unused = [(nm, ln) for nm, ln in imports.items()
              if nm not in loaded and nm not in text_all and not _ignored(sc.lines, ln) and "noqa" not in sc.lines[ln - 1]]
    return unused


def scan(text, filename=""):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [{"rule": "BUG001", "line": e.lineno or 1, "msg": "Syntax error: %s" % (e.msg,)}]
    except ValueError as e:          # e.g. null bytes
        return [{"rule": "BUG001", "line": 1, "msg": "File cannot be parsed: %s" % e}]
    sc = _Scanner(text)
    sc.no_encoding = []
    sc.visit(tree)
    _check_blocks(tree, sc)
    unused = _check_names(tree, sc)
    if sc.no_encoding:
        ls = sc.no_encoding
        sc.add("BUG007", ls[0], "%d open() call(s) without encoding= in this file (lines %s)."
               % (len(ls), ", ".join(map(str, ls[:12])) + (" ..." if len(ls) > 12 else "")))
    if unused and not filename.endswith("__init__.py"):
        sc.add("BUG008", unused[0][1], "Unused import(s): %s." % ", ".join(n for n, _ in unused[:15]))
    # PY019 CSV formula injection (one per file)
    t = text
    if re.search(r"csv\.(writer|DictWriter)|\.to_csv\(", t) and re.search(r"request|send_file|Response\(", t) and \
            not re.search(r"formula|['\"]=\+-@['\"]|['\"]=['\"]\s*,\s*['\"]\+['\"]", t):
        for i, ln in enumerate(sc.lines, 1):
            if re.search(r"csv\.(writer|DictWriter)|\.to_csv\(", ln):
                sc.add("PY019", i, "CSV is exported without escaping values that start with = + - @.")
                break
    # de-duplicate (same rule + line)
    seen, out = set(), []
    for f in sc.out:
        k = (f["rule"], f["line"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def has_auth(text):
    """Does this code contain any kind of sign-in / password check?"""
    return bool(re.search(r"login_required|flask_login|check_password|verify_password|HTTPBasicAuth|requires_auth|"
                          r"session\[['\"](user|logged|auth)|def\s+login|authenticate\(|check_pin|pin_hash|"
                          r"@auth\.|before_request[\s\S]{0,400}(401|403|login)", text))
