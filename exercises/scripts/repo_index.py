#!/usr/bin/env python3
"""
repo_index.py: deterministic repository index for path-centric security work.

Step 1 of the path-centric audit architecture (playbook §5.7): BEFORE any
model call, build a structural index of the repo: files, imports, function
definitions with line ranges, decorators, a best-effort static call graph,
detected entry points (HTTP routes, CLI mains, tasks), and per-function
taint markers (where request data enters, where dangerous sinks live).

Parsing is done with Tree-sitter, the same incremental, error-tolerant
parser library used by GitHub code navigation, Neovim, and most modern
static-analysis tooling. Tree-sitter gives us one structural layer across
languages instead of a different parser per language; grammars currently
loaded: Python, JavaScript, TypeScript/TSX. (If Tree-sitter is not
installed, Python files fall back to the stdlib `ast` module.)

Two honest limits:
  * Tree-sitter builds syntax trees; it does not resolve names. The call
    graph edges come from our own best-effort name resolution on top of the
    trees (direct calls, self./this. calls, import-resolved module calls).
    Dynamic dispatch, decorators that wrap behavior, and string-based
    routing stay invisible. Treat "no path found" as "no path found
    statically", never as "safe".
  * Languages without a loaded grammar are indexed by path and size only;
    path_audit.py audits them as whole-file bundles.

Everything here is deterministic: no model, no network. The output
(`repo-index.json`) is evidence: it records what the analyzer could see,
which is what makes "coverage" a checkable property.

Usage:
    python3 scripts/repo_index.py ../sample-vuln-app --out ./out/repo-index.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Reuse the audit pack's file walker so both tools agree on scope (CI config
# dirs and extensionless security-critical files included; see code_audit).
from code_audit import iter_repo_files  # noqa: E402
from code_audit import HEURISTIC_SINKS, HEURISTIC_SKIP_LINE  # noqa: E402

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as _ts_python
    import tree_sitter_javascript as _ts_javascript
    import tree_sitter_typescript as _ts_typescript
    TS_AVAILABLE = True
except ImportError:  # stdlib fallback covers Python only
    TS_AVAILABLE = False

MAX_FORWARD_DEPTH = 6      # entry-point -> sink tracing depth
MAX_BACKWARD_DEPTH = 3     # sink -> callers tracing depth
MAX_BUNDLE_NODES = 25      # cap on functions per path bundle

# Decorator suffixes that mark an HTTP entry point (Flask, FastAPI, Django
# REST, Bottle, ...). Matched against the dotted decorator name.
ROUTE_DECORATOR_SUFFIXES = (
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "api_view", "websocket",
)
TASK_DECORATOR_SUFFIXES = ("task", "shared_task", "celery_app.task")
# Hand-written handler shapes: def view(request): ... (Django/Flask style).
HANDLER_FIRST_ARGS = {"request", "req", "event"}
# JS/TS route-registration methods (Express, Fastify, Koa, Hono, ...).
JS_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "all", "use",
                    "route", "listen"}

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
}


@dataclass
class FunctionInfo:
    qualname: str                 # module.Class.method  or  module.func
    name: str
    file: str                     # repo-relative path
    start_line: int
    end_line: int
    decorators: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)        # raw dotted names
    sources: list[str] = field(default_factory=list)      # request data markers
    sinks: list[str] = field(default_factory=list)        # heuristic sink hits
    is_entry_point: bool = False
    entry_kind: str = ""          # "http-route" | "cli-main" | "task" | "handler-shape"
    route: str = ""               # "/user" etc., when known


@dataclass
class FileInfo:
    path: str
    size: int
    language: str                 # "python" | "javascript" | "typescript" | "tsx" | "other"
    imports: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)    # qualnames
    parse_error: str = ""


@dataclass
class RepoIndex:
    root: str
    generated: str
    parser: str = ""              # "tree-sitter 0.x" or "python ast fallback"
    files: dict = field(default_factory=dict)       # rel -> FileInfo
    functions: dict = field(default_factory=dict)   # qualname -> FunctionInfo
    call_graph: dict = field(default_factory=dict)  # qualname -> [callee qualnames]
    callers: dict = field(default_factory=dict)     # qualname -> [caller qualnames]
    entry_points: list = field(default_factory=list)  # qualnames
    skipped: list = field(default_factory=list)

    def forward(self, start: str, depth: int = MAX_FORWARD_DEPTH,
                cap: int = MAX_BUNDLE_NODES) -> list[str]:
        """BFS over the call graph from `start`; returns qualnames, start first."""
        seen, order, frontier = {start}, [start], [(start, 0)]
        while frontier and len(order) < cap:
            node, d = frontier.pop(0)
            if d >= depth:
                continue
            for nxt in self.call_graph.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    order.append(nxt)
                    frontier.append((nxt, d + 1))
        return order

    def backward(self, start: str, depth: int = MAX_BACKWARD_DEPTH,
                 cap: int = MAX_BUNDLE_NODES) -> list[str]:
        """BFS over the reverse graph (who can reach this function?)."""
        seen, order, frontier = {start}, [start], [(start, 0)]
        while frontier and len(order) < cap:
            node, d = frontier.pop(0)
            if d >= depth:
                continue
            for nxt in self.callers.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    order.append(nxt)
                    frontier.append((nxt, d + 1))
        return order


# ---------------------------------------------------------------------------
# Taint markers (language-agnostic regexes on function source)
# ---------------------------------------------------------------------------

SOURCE_PATTERNS = (
    # Python web frameworks
    "request.args", "request.form", "request.get_data", "request.data",
    "request.json", "request.values", "request.headers", "request.cookies",
    "request.files", "request.get_json", "sys.argv", "input(",
    # JS/TS servers (Express & friends)
    "req.query", "req.body", "req.params", "req.headers", "req.cookies",
    "process.argv",
)


def _function_markers(source: str) -> tuple[list[str], list[str]]:
    sources = [p for p in SOURCE_PATTERNS if p in source]
    sinks: list[str] = []
    for line in source.splitlines():
        if HEURISTIC_SKIP_LINE.match(line):
            continue
        for pattern, _cat, desc, _sev in HEURISTIC_SINKS:
            if _cat == "surface":
                continue
            if re.search(pattern, line):
                sinks.append(desc)
                break
    return sources, sorted(set(sinks))


def module_name_for(rel: str) -> str:
    p = Path(rel).with_suffix("")
    return ".".join(p.parts)


def _route_string(arg_text: str) -> str:
    m = re.match(r"""^["'`]([^"'`]+)["'`]""", arg_text.strip())
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Tree-sitter extraction
# ---------------------------------------------------------------------------

if TS_AVAILABLE:
    _PY_LANG = Language(_ts_python.language())
    _JS_LANG = Language(_ts_javascript.language())
    _TS_LANG = Language(_ts_typescript.language_typescript())
    _TSX_LANG = Language(_ts_typescript.language_tsx())
    _LANG_OBJ = {"python": _PY_LANG, "javascript": _JS_LANG,
                 "typescript": _TS_LANG, "tsx": _TSX_LANG}
    _PARSERS = {name: Parser(lang) for name, lang in _LANG_OBJ.items()}


def _node_dotted(node) -> str:
    """Dotted name from tree-sitter identifier/attribute/member chains."""
    if node is None:
        return ""
    if node.type in ("identifier", "property_identifier", "shorthand_property_identifier"):
        return node.text.decode()
    if node.type in ("attribute", "member_expression"):
        obj = node.child_by_field_name("object")
        attr = (node.child_by_field_name("attribute")
                or node.child_by_field_name("property"))
        base = _node_dotted(obj)
        leaf = _node_dotted(attr)
        if base and leaf:
            return f"{base}.{leaf}"
        return base or leaf
    if node.type in ("call", "call_expression"):
        return _node_dotted(node.child_by_field_name("function"))
    if node.type == "dotted_name":
        return node.text.decode()
    return ""


def _walk_calls(node, out: set) -> None:
    if node.type in ("call", "call_expression"):
        name = _node_dotted(node.child_by_field_name("function"))
        if name:
            out.add(name)
    for child in node.children:
        _walk_calls(child, out)


def _ts_python_extract(rel: str, text: str, module: str, root_node,
                       lines: list[str], index: RepoIndex) -> None:
    info = index.files[rel]
    alias_map: dict[str, str] = {}

    def span(node) -> tuple[int, int]:
        start = node.start_point[0] + 1
        end = node.end_point[0] + (1 if node.end_point[1] > 0 else 0)
        return start, max(end, start)

    def src_of(start: int, end: int) -> str:
        return "\n".join(lines[start - 1:end])

    def record_function(node, qual: str,
                        decorators: list[tuple[str, str]]) -> None:
        start, end = span(node)
        calls: set[str] = set()
        _walk_calls(node, calls)
        sources, sinks = _function_markers(src_of(start, end))
        dec_names = [d for d, _arg in decorators]
        fi = FunctionInfo(qualname=qual, name=qual.rsplit(".", 1)[-1],
                          file=rel, start_line=start, end_line=end,
                          decorators=dec_names,
                          calls=sorted(calls), sources=sources, sinks=sinks)
        last_decs = {d.rsplit(".", 1)[-1] for d in dec_names}
        if last_decs & set(ROUTE_DECORATOR_SUFFIXES):
            fi.is_entry_point, fi.entry_kind = True, "http-route"
            fi.route = next((_route_string(arg) for d, arg in decorators
                             if d.rsplit(".", 1)[-1] in ROUTE_DECORATOR_SUFFIXES
                             and _route_string(arg)), "")
        elif last_decs & set(TASK_DECORATOR_SUFFIXES):
            fi.is_entry_point, fi.entry_kind = True, "task"
        else:
            params = node.child_by_field_name("parameters")
            if params is not None and params.children:
                first = params.children[1] if len(params.children) > 1 else None
                if first is not None and first.type == "identifier" \
                        and first.text.decode() in HANDLER_FIRST_ARGS:
                    fi.is_entry_point, fi.entry_kind = True, "handler-shape"
        index.functions[qual] = fi
        info.functions.append(qual)

    def visit(node, prefix: str, decorators: list[tuple[str, str]]) -> None:
        for child in node.children:
            t = child.type
            if t == "import_statement":
                for sub in child.children:
                    if sub.type == "dotted_name":
                        name = sub.text.decode()
                        alias_map[name.split(".")[0]] = name
                        info.imports.append(name)
                    elif sub.type == "aliased_import":
                        name_node = sub.child_by_field_name("name")
                        alias_node = sub.child_by_field_name("alias")
                        if name_node is not None:
                            name = name_node.text.decode()
                            alias_map[alias_node.text.decode() if alias_node
                                      else name.split(".")[0]] = name
                            info.imports.append(name)
            elif t == "import_from_statement":
                mod_node = child.child_by_field_name("module_name")
                mod = mod_node.text.decode() if mod_node else ""
                if mod:
                    info.imports.append(mod)
                for sub in child.children:
                    if sub.type in ("dotted_name", "identifier") and sub is not mod_node:
                        alias_map[sub.text.decode()] = f"{mod}.{sub.text.decode()}" if mod else sub.text.decode()
                    elif sub.type == "aliased_import":
                        name_node = sub.child_by_field_name("name")
                        alias_node = sub.child_by_field_name("alias")
                        if name_node is not None:
                            n = name_node.text.decode()
                            alias_map[alias_node.text.decode() if alias_node else n] = f"{mod}.{n}"
            elif t == "decorated_definition":
                decs: list[tuple[str, str]] = []
                definition = None
                for sub in child.children:
                    if sub.type == "decorator":
                        expr = sub.children[1] if len(sub.children) > 1 else None
                        d = _node_dotted(expr)
                        arg_text = ""
                        if expr is not None and expr.type == "call":
                            args = expr.child_by_field_name("arguments")
                            if args is not None and len(args.children) > 1:
                                arg_text = args.children[1].text.decode()
                        if d:
                            decs.append((d, arg_text))
                    elif sub.type in ("function_definition", "class_definition"):
                        definition = sub
                if definition is not None:
                    if definition.type == "function_definition":
                        name_node = definition.child_by_field_name("name")
                        if name_node is not None:
                            qual = f"{prefix}.{name_node.text.decode()}"
                            record_function(definition, qual, decs)
                            visit(definition, qual, [])
                    else:
                        visit(definition, prefix, [])
            elif t == "function_definition":
                name_node = child.child_by_field_name("name")
                if name_node is None:
                    continue
                name = name_node.text.decode()
                qual = f"{prefix}.{name}"
                record_function(child, qual, [])
                visit(child, qual, [])
            elif t == "class_definition":
                name_node = child.child_by_field_name("name")
                cname = name_node.text.decode() if name_node else "anon"
                visit(child, f"{prefix}.{cname}", [])
            elif t == "if_statement" and prefix == module:
                cond = child.child_by_field_name("condition")
                if cond is not None and "__name__" in cond.text.decode():
                    start, end = span(child)
                    calls: set[str] = set()
                    _walk_calls(child, calls)
                    sources, sinks = _function_markers(src_of(start, end))
                    qual = f"{module}.__main__"
                    index.functions[qual] = FunctionInfo(
                        qualname=qual, name="__main__", file=rel,
                        start_line=start, end_line=end, calls=sorted(calls),
                        sources=sources, sinks=sinks,
                        is_entry_point=True, entry_kind="cli-main")
                    info.functions.append(qual)
            else:
                visit(child, prefix, [])

    visit(root_node, module, [])
    info._alias_map = alias_map  # type: ignore[attr-defined]


def _ts_js_extract(rel: str, text: str, module: str, root_node,
                   lines: list[str], index: RepoIndex) -> None:
    info = index.files[rel]
    alias_map: dict[str, str] = {}
    pending_route_refs: list[tuple[str, str]] = []  # (dotted handler ref, route)

    def span(node) -> tuple[int, int]:
        start = node.start_point[0] + 1
        end = node.end_point[0] + (1 if node.end_point[1] > 0 else 0)
        return start, max(end, start)

    def record_function(node, qual: str, route: str = "") -> None:
        start, end = span(node)
        calls: set[str] = set()
        _walk_calls(node, calls)
        sources, sinks = _function_markers("\n".join(lines[start - 1:end]))
        fi = FunctionInfo(qualname=qual, name=qual.rsplit(".", 1)[-1],
                          file=rel, start_line=start, end_line=end,
                          calls=sorted(calls), sources=sources, sinks=sinks)
        if route:
            fi.is_entry_point, fi.entry_kind, fi.route = True, "http-route", route
        index.functions[qual] = fi
        info.functions.append(qual)

    def check_route_call(node) -> None:
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return
        prop = fn.child_by_field_name("property")
        if prop is None or prop.text.decode() not in JS_ROUTE_METHODS:
            return
        args = node.child_by_field_name("arguments")
        if args is None or len(args.children) < 3:
            return
        inner = [c for c in args.children
                 if c.type not in (",", "(", ")", "comment")]
        if not inner:
            return
        route = _route_string(inner[0].text.decode())
        if not route:
            return
        handler = inner[1] if len(inner) > 1 else None
        if handler is None:
            return
        if handler.type in ("arrow_function", "function_expression", "function"):
            safe = re.sub(r"[^A-Za-z0-9]+", "_", route).strip("_") or "root"
            qual = f"{module}.handler_{prop.text.decode()}_{safe}"
            record_function(handler, qual, route=route)
        else:
            ref = _node_dotted(handler)
            if ref:
                pending_route_refs.append((ref, route))

    def visit(node, prefix: str) -> None:
        for child in node.children:
            t = child.type
            if t == "import_statement":
                src = child.child_by_field_name("source")
                if src is not None:
                    mod = src.text.decode().strip("\"'")
                    info.imports.append(mod)
                    clause = next((c for c in child.children
                                   if c.type == "import_clause"), None)
                    if clause is not None:
                        for sub in clause.children:
                            if sub.type == "identifier":
                                alias_map[sub.text.decode()] = mod
                            elif sub.type == "named_imports":
                                for spec in sub.children:
                                    if spec.type == "import_specifier":
                                        name_node = spec.child_by_field_name("name")
                                        alias_node = spec.child_by_field_name("alias")
                                        if name_node is not None:
                                            alias_map[(alias_node or name_node).text.decode()] = \
                                                f"{mod}.{name_node.text.decode()}"
            elif t == "function_declaration":
                name_node = child.child_by_field_name("name")
                if name_node is None:
                    continue
                qual = f"{prefix}.{name_node.text.decode()}"
                record_function(child, qual)
                visit(child, qual)
            elif t == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if value_node is not None and value_node.type in (
                        "arrow_function", "function_expression", "function"):
                    qual = f"{prefix}.{name_node.text.decode()}" \
                        if name_node is not None else f"{prefix}.anon_{child.start_point[0]}"
                    record_function(value_node, qual)
                    visit(value_node, qual)
                elif (value_node is not None and value_node.type == "call_expression"
                        and name_node is not None
                        and _node_dotted(value_node.child_by_field_name("function")) == "require"):
                    arg = value_node.child_by_field_name("arguments")
                    if arg is not None:
                        mod = arg.text.decode().strip("()\"'`, ")
                        alias_map[name_node.text.decode()] = mod
                        info.imports.append(mod)
            elif t == "method_definition":
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    record_function(child, f"{prefix}.{name_node.text.decode()}")
            elif t == "class_declaration":
                name_node = child.child_by_field_name("name")
                cname = name_node.text.decode() if name_node else "anon"
                visit(child, f"{prefix}.{cname}")
            else:
                visit(child, prefix)
        if node.type == "call_expression":
            check_route_call(node)

    visit(root_node, module)

    # Resolve route registrations that referenced named handlers.
    for ref, route in pending_route_refs:
        for cand in (f"{module}.{ref}", ref):
            if cand in index.functions:
                fi = index.functions[cand]
                fi.is_entry_point, fi.entry_kind, fi.route = True, "http-route", route
                break
    info._alias_map = alias_map  # type: ignore[attr-defined]


def tree_sitter_extract(rel: str, text: str, module: str, language: str,
                        index: RepoIndex) -> None:
    parser = _PARSERS[language]
    tree = parser.parse(text.encode())
    lines = text.splitlines()
    if language == "python":
        _ts_python_extract(rel, text, module, tree.root_node, lines, index)
    else:
        _ts_js_extract(rel, text, module, tree.root_node, lines, index)


# ---------------------------------------------------------------------------
# Stdlib ast fallback (Python only, used when tree-sitter is not installed)
# ---------------------------------------------------------------------------

def ast_fallback_extract(rel: str, text: str, module: str,
                         index: RepoIndex) -> None:
    import ast
    info = index.files[rel]
    tree = ast.parse(text)
    lines = text.splitlines()
    alias_map: dict[str, str] = {}

    def dotted(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return dotted(node.func)
        return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                alias_map[a.asname or a.name.split(".")[0]] = a.name
                info.imports.append(a.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                alias_map[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
            if mod:
                info.imports.append(mod)

    def visit(node, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{child.name}"
                decs = [d for d in (dotted(x) for x in child.decorator_list) if d]
                start = child.lineno
                end = getattr(child, "end_lineno", child.lineno) or child.lineno
                body = "\n".join(lines[start - 1:end])
                calls = sorted({dotted(c.func) for c in ast.walk(child)
                                if isinstance(c, ast.Call) and dotted(c.func)})
                sources, sinks = _function_markers(body)
                fi = FunctionInfo(qualname=qual, name=child.name, file=rel,
                                  start_line=start, end_line=end, decorators=decs,
                                  calls=calls, sources=sources, sinks=sinks)
                last = {d.rsplit(".", 1)[-1] for d in decs}
                if last & set(ROUTE_DECORATOR_SUFFIXES):
                    fi.is_entry_point, fi.entry_kind = True, "http-route"
                    for d in child.decorator_list:
                        if isinstance(d, ast.Call) and d.args and isinstance(
                                d.args[0], ast.Constant):
                            fi.route = fi.route or str(d.args[0].value)
                elif last & set(TASK_DECORATOR_SUFFIXES):
                    fi.is_entry_point, fi.entry_kind = True, "task"
                elif child.args.args and child.args.args[0].arg in HANDLER_FIRST_ARGS:
                    fi.is_entry_point, fi.entry_kind = True, "handler-shape"
                index.functions[qual] = fi
                info.functions.append(qual)
                visit(child, qual)
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}.{child.name}")
            elif isinstance(child, ast.If) and prefix == module:
                test = child.test
                if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                        and test.left.id == "__name__"):
                    end = getattr(child, "end_lineno", child.lineno) or child.lineno
                    body = "\n".join(lines[child.lineno - 1:end])
                    calls = sorted({dotted(c.func) for c in ast.walk(child)
                                    if isinstance(c, ast.Call) and dotted(c.func)})
                    sources, sinks = _function_markers(body)
                    qual = f"{module}.__main__"
                    index.functions[qual] = FunctionInfo(
                        qualname=qual, name="__main__", file=rel,
                        start_line=child.lineno, end_line=end, calls=calls,
                        sources=sources, sinks=sinks,
                        is_entry_point=True, entry_kind="cli-main")
                    info.functions.append(qual)

    visit(tree, module)
    info._alias_map = alias_map  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Graph construction (best-effort static resolution, language-agnostic)
# ---------------------------------------------------------------------------

def _normalize_import(mod: str, from_file: str) -> str:
    """Resolve JS/TS relative imports to module qualnames."""
    if not mod.startswith("."):
        return mod.replace("/", ".")
    base = Path(from_file).parent
    parts = []
    for piece in (base / mod).parts:
        if piece in (".", ""):
            continue
        if piece == "..":
            if parts:
                parts.pop()
        else:
            parts.append(piece)
    return ".".join(parts)


def resolve_calls(index: RepoIndex) -> None:
    def candidates(fi: FunctionInfo, raw: str) -> list[str]:
        module = module_name_for(fi.file)
        prefix = fi.qualname[: -len(fi.name) - 1]
        out: list[str] = []
        parts = raw.split(".")
        alias_map = getattr(index.files[fi.file], "_alias_map", {})
        if parts[0] in ("self", "this") and len(parts) > 1:
            out.append(f"{prefix}.{'.'.join(parts[1:])}")
            if "." in prefix:
                out.append(".".join(prefix.split(".")[:-1] + parts[1:]))
        if raw in alias_map:
            out.append(_normalize_import(alias_map[raw], fi.file))
        elif parts[0] in alias_map and len(parts) > 1:
            out.append(".".join([_normalize_import(alias_map[parts[0]], fi.file)]
                                + parts[1:]))
        scope = prefix
        while scope:
            out.append(f"{scope}.{raw}")
            scope = scope.rsplit(".", 1)[0] if "." in scope else ""
        out.append(f"{module}.{raw}")
        out.append(raw)
        return out

    for qual, fi in index.functions.items():
        edges: set[str] = set()
        for raw in fi.calls:
            for cand in candidates(fi, raw):
                if cand in index.functions and cand != qual:
                    edges.add(cand)
                    break
        index.call_graph[qual] = sorted(edges)
    callers: dict[str, set[str]] = {}
    for caller, callees in index.call_graph.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    index.callers = {k: sorted(v) for k, v in callers.items()}


# ---------------------------------------------------------------------------
# Top-level build
# ---------------------------------------------------------------------------

def build_index(root: Path) -> RepoIndex:
    root = root.resolve()
    parser_desc = "tree-sitter" if TS_AVAILABLE else "python ast fallback"
    index = RepoIndex(root=str(root),
                      generated=time.strftime("%Y-%m-%d %H:%M:%S"),
                      parser=parser_desc)
    files, skipped = iter_repo_files(root)
    index.skipped = skipped
    for path in files:
        rel = str(path.relative_to(root))
        try:
            size = path.stat().st_size
        except OSError:
            continue
        language = LANG_BY_EXT.get(path.suffix.lower(), "other")
        info = FileInfo(path=rel, size=size, language=language)
        index.files[rel] = info
        if language == "other":
            continue
        try:
            text = path.read_text(errors="replace")
            if TS_AVAILABLE:
                tree_sitter_extract(rel, text, module_name_for(rel), language, index)
            elif language == "python":
                ast_fallback_extract(rel, text, module_name_for(rel), index)
        except Exception as exc:  # syntax errors and grammar gaps must not
            info.parse_error = str(exc)[:200]  # kill the whole index
    resolve_calls(index)
    index.entry_points = sorted(q for q, f in index.functions.items()
                                if f.is_entry_point)
    return index


def index_to_json(index: RepoIndex) -> dict:
    files = {rel: asdict(fi) for rel, fi in index.files.items()}
    for rel in files:
        files[rel].pop("_alias_map", None)
    return {
        "root": index.root,
        "generated": index.generated,
        "parser": index.parser,
        "files": files,
        "functions": {q: asdict(f) for q, f in index.functions.items()},
        "call_graph": index.call_graph,
        "callers": index.callers,
        "entry_points": index.entry_points,
        "skipped": index.skipped,
    }


def summarize(index: RepoIndex) -> str:
    langs: dict[str, int] = {}
    for f in index.files.values():
        langs[f.language] = langs.get(f.language, 0) + 1
    lang_str = ", ".join(f"{v} {k}" for k, v in sorted(langs.items()))
    lines = [
        f"Repository: {index.root}",
        f"Parser: {index.parser}",
        f"Files indexed: {len(index.files)} ({lang_str}), "
        f"skipped: {len(index.skipped)}",
        f"Functions: {len(index.functions)}",
        f"Call-graph edges: {sum(len(v) for v in index.call_graph.values())}",
        f"Entry points ({len(index.entry_points)}):",
    ]
    for q in index.entry_points:
        f = index.functions[q]
        route = f" {f.route}" if f.route else ""
        lines.append(f"  - [{f.entry_kind}]{route} {q} ({f.file}:{f.start_line})")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic repo index built on "
                                           "Tree-sitter (call graph, entry points, "
                                           "taint markers)")
    ap.add_argument("repo", help="path to the repository")
    ap.add_argument("--out", default=None,
                    help="write JSON index here (default: print summary only)")
    args = ap.parse_args()
    root = Path(args.repo)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    index = build_index(root)
    print(summarize(index))
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(index_to_json(index), indent=2))
        print(f"\nIndex written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
