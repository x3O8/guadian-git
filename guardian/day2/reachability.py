"""Package-level reachability: which installed packages the application's own code actually imports.

Source files are read as text (require/import statements). Nothing is executed. This is package-level,
not function-level: it tells us whether vulnerable code can be loaded by the app at all, and through
which of the app's imports.
"""
import re
from collections import defaultdict
from pathlib import Path

EXTS = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".nyc_output", "vendor", "bower_components", ".next"}
TEST_HINTS = ("test/", "tests/", "spec/", "__tests__/", "cypress/", "e2e/", ".test.", ".spec.", "/mocks/", "fixtures/")
TOOLING_HINTS = ("scripts/", "tools/", "config/", ".config.", "gulpfile", "gruntfile", "webpack", "rollup", "vite.config",
                 "eslint", "karma", "jest.config", "babel.config")
IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*|import\s*\(\s*|from\s+|import\s+)['"]([^'"\s]+)['"]""")
BUILTINS = {"fs", "path", "http", "https", "crypto", "os", "url", "util", "stream", "events", "zlib", "child_process",
            "net", "tls", "dns", "assert", "buffer", "querystring", "readline", "cluster", "vm", "worker_threads",
            "process", "timers", "string_decoder", "perf_hooks", "module", "dgram", "v8", "async_hooks", "inspector",
            "http2", "punycode", "constants", "domain", "tty", "repl", "test"}


def package_of(spec: str):
    if spec.startswith((".", "/", "node:", "~", "#", "data:", "http:", "https:")) or "${" in spec:
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    return None if name in BUILTINS or not name else name


def classify(rel: str) -> str:
    low = rel.lower()
    if any(h in low for h in TEST_HINTS):
        return "test"
    if any(h in low for h in TOOLING_HINTS):
        return "tooling"
    return "runtime"


def nested_package_dirs(repo: Path) -> set[Path]:
    """Sub-folders with their own package.json (e.g. frontend/) have their own dependency tree."""
    return {p.parent for p in repo.rglob("package.json")
            if p.parent != repo and not (set(p.relative_to(repo).parts) & SKIP_DIRS)}


def scan_imports(repo: Path, limit_files: int = 6000) -> dict:
    """{package: {"runtime": [files], "test": [...], "tooling": [...]}} for code belonging to the root package."""
    repo = Path(repo)
    nested = nested_package_dirs(repo)
    found = defaultdict(lambda: defaultdict(list))
    count = 0
    for f in repo.rglob("*"):
        if f.suffix not in EXTS or not f.is_file():
            continue
        rel_parts = set(f.relative_to(repo).parts)
        if rel_parts & SKIP_DIRS or any(n in f.parents for n in nested):
            continue
        count += 1
        if count > limit_files:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = f.relative_to(repo).as_posix()
        kind = classify(rel)
        for spec in set(IMPORT_RE.findall(text)):
            pkg = package_of(spec)
            if pkg:
                found[pkg][kind].append(rel)
    return {p: {k: sorted(v) for k, v in kinds.items()} for p, kinds in found.items()}


def literal_refs(repo: Path, names: set) -> dict:
    """Packages loaded by name at run time (e.g. app.set('view engine', 'hbs')) don't appear as imports.
    Find runtime files that mention the exact package name as a quoted string."""
    repo, names = Path(repo), set(names)
    pats = {n: re.compile(r"""['"]""" + re.escape(n) + r"""['"]""") for n in names}
    nested = nested_package_dirs(repo)
    hits = defaultdict(list)
    for f in repo.rglob("*"):
        if f.suffix not in EXTS or not f.is_file() or set(f.relative_to(repo).parts) & SKIP_DIRS \
                or any(n in f.parents for n in nested):
            continue
        rel = f.relative_to(repo).as_posix()
        if classify(rel) != "runtime":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for n, pat in pats.items():
            if pat.search(text):
                hits[n].append(rel)
    return dict(hits)


def is_network_service(repo: Path, imports: dict) -> bool:
    servers = {"express", "koa", "fastify", "@hapi/hapi", "hapi", "restify", "@nestjs/core", "next", "socket.io", "http-server"}
    return any(s in imports and imports[s].get("runtime") for s in servers)


def reachability(pkg: str, direct: bool, scope: str, introduced_via: list, imports: dict, literals: dict = None) -> dict:
    """Decide how the app can reach an installed package. Returns level, points-ready label and evidence."""
    own = imports.get(pkg, {})
    if direct and own.get("runtime"):
        return {"level": "imported", "label": f"imported by application code in {len(own['runtime'])} file(s)",
                "files": own["runtime"][:8], "via": [], "decided": True}
    via_hits = []
    for parent in introduced_via or []:
        pname = parent.rsplit("@", 1)[0] if "@" in parent[1:] else parent
        hit = imports.get(pname, {})
        if hit.get("runtime"):
            via_hits.append((pname, hit["runtime"]))
    if via_hits:
        p, files = via_hits[0]
        return {"level": "via-import", "label": f"loaded through {p}, which application code imports in {len(files)} file(s)",
                "files": files[:8], "via": [p for p, _ in via_hits], "decided": True}
    if scope == "dev":
        where = own.get("test") or own.get("tooling") or []
        return {"level": "dev", "label": "development/test tooling only" + (f" (used in {len(where)} test or tooling files)" if where else ""),
                "files": where[:8], "via": [], "decided": True}
    if direct and (own.get("test") or own.get("tooling")):
        where = own.get("test", []) + own.get("tooling", [])
        return {"level": "not-imported", "label": f"shipped but only imported by tests or tooling ({len(where)} files)",
                "files": where[:8], "via": [], "decided": True}
    named = (literals or {}).get(pkg)
    if direct and named:
        return {"level": "imported", "label": f"loaded by name at run time in {len(named)} file(s) (no import statement)",
                "files": named[:8], "via": [], "decided": True}
    return {"level": "not-imported", "label": "shipped, but no import from application code was found",
            "files": [], "via": [], "decided": False}
