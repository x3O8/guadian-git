"""Fetch a public GitHub repo into target/ and prepare a resolved package-lock.json.

Nothing from the fetched repository is executed: git clone + npm --package-lock-only --ignore-scripts.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from guardian.agents.sbom import find_tool

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "target"
NAME = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}"
URL_RE = re.compile(rf"^(?:https?://)?(?:www\.)?github\.com/({NAME})/({NAME}?)(?:\.git)?(?:/(?:tree|blob|commits?|issues|pulls?)(?:/.*)?)?/?(?:[?#].*)?$")
SHORT_RE = re.compile(rf"^({NAME})/({NAME})$")
OTHER_ECOSYSTEMS = {
    "requirements.txt": "Python", "pyproject.toml": "Python", "setup.py": "Python", "Pipfile": "Python",
    "pom.xml": "Java (Maven)", "build.gradle": "Java (Gradle)", "build.gradle.kts": "Kotlin (Gradle)",
    "go.mod": "Go", "Cargo.toml": "Rust", "Gemfile": "Ruby", "composer.json": "PHP", "packages.config": ".NET",
}
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # fail fast on private/missing repos instead of prompting


class FetchError(RuntimeError):
    pass


def parse_github_url(url: str) -> tuple[str, str]:
    url = url.strip()
    m = URL_RE.match(url) or SHORT_RE.match(url)
    if not m:
        raise FetchError("Not a valid GitHub repository link. Use https://github.com/<owner>/<repo>.")
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo:
        raise FetchError("The link has no repository name.")
    return owner, repo


def run(cmd: list, cwd=None, timeout=900) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=GIT_ENV)


def origin_of(path: Path):
    proc = run(["git", "-C", str(path), "remote", "get-url", "origin"])
    return proc.stdout.strip().lower().removesuffix(".git") if proc.returncode == 0 else None


def remove_tree(path: Path):
    def force(func, p, _):
        os.chmod(p, 0o700)
        func(p)
    shutil.rmtree(path, onerror=force)


def target_dir(owner: str, repo: str) -> Path:
    canonical = f"https://github.com/{owner}/{repo}".lower()
    plain = TARGETS / repo
    if not plain.exists() or origin_of(plain) == canonical:
        return plain
    return TARGETS / f"{owner}--{repo}"


def clone(owner: str, repo: str, dest: Path, refresh: bool, log):
    url = f"https://github.com/{owner}/{repo}.git"
    if dest.exists() and not refresh:
        log(f"Using existing clone in target/{dest.name} (tick 're-clone' to refresh)")
        return
    if dest.exists():
        log(f"Removing old clone target/{dest.name}")
        remove_tree(dest)
    log(f"Cloning {url} (shallow, long paths enabled)")
    TARGETS.mkdir(exist_ok=True)
    proc = run(["git", "-c", "core.longpaths=true", "clone", "--depth", "200", url, str(dest)])
    if proc.returncode != 0:
        if dest.exists():
            remove_tree(dest)
        err = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "unknown error"
        if "not found" in err.lower() or "could not read username" in err.lower():
            err = "Repository not found or private. Only public GitHub repos are supported."
        raise FetchError(f"git clone failed: {err}")


def check_npm_project(dest: Path):
    if (dest / "package.json").exists():
        return
    found = sorted({lang for f, lang in OTHER_ECOSYSTEMS.items() if (dest / f).exists()})
    nested = [p.relative_to(dest).as_posix() for p in dest.glob("*/package.json")][:5]
    msg = "No package.json at the repository root, so this is not an npm/Node.js project."
    if found:
        msg += f" It looks like a {', '.join(found)} project. Day 1 Guardian supports npm only."
    if nested:
        msg += f" (package.json found in sub-folders: {', '.join(nested)} — monorepos are not supported yet.)"
    raise FetchError(msg)


def lockfile_ok(dest: Path) -> bool:
    lock = dest / "package-lock.json"
    if not lock.exists():
        return False
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return data.get("lockfileVersion", 1) >= 2 and "packages" in data


def ensure_lockfile(dest: Path, log):
    if lockfile_ok(dest):
        log("Repository already has a package-lock.json (v2/v3) — using it as-is")
        return "existing"
    other = [f for f in ("yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json") if (dest / f).exists()]
    log("Generating package-lock.json with npm --package-lock-only --ignore-scripts (no repo code runs)"
        + (f"; note: repo uses {', '.join(other)}, npm resolution may differ slightly" if other else ""))
    npm = find_tool("npm") or "npm"
    base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
            "--no-audit", "--no-fund"]
    proc = run(base, cwd=dest)
    if proc.returncode != 0 and "ERESOLVE" in proc.stderr:
        log("Peer-dependency conflict; retrying with --legacy-peer-deps")
        proc = run(base + ["--legacy-peer-deps"], cwd=dest)
    if proc.returncode != 0 or not lockfile_ok(dest):
        tail = "\n".join(proc.stderr.strip().splitlines()[-6:])
        raise FetchError(f"npm could not resolve the dependency tree:\n{tail}")
    return "generated"


def fetch(url: str, refresh: bool = False, log=print) -> Path:
    owner, repo = parse_github_url(url)
    log(f"Valid GitHub repository: {owner}/{repo}")
    dest = target_dir(owner, repo)
    clone(owner, repo, dest, refresh, log)
    try:
        check_npm_project(dest)
    except FetchError:
        remove_tree(dest)  # don't keep non-npm clones around
        raise
    log("package.json found — npm project")
    ensure_lockfile(dest, log)
    return dest


def out_dir_for(repo: Path) -> Path:
    reports = ROOT / "reports"
    if repo.name == "juice-shop":
        return reports
    return reports / repo.name
