import json
import re
import subprocess
from pathlib import Path

from guardian.lockfile import load_lock, name_from_path
from guardian.models import Component, Inventory, Manifest

SKIP_DIRS = {"node_modules", ".git", "dist", ".angular"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def classify_npm_range(rng: str) -> str:
    if re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", rng):
        return "exact"
    if rng.startswith(("git", "github:", "http", "file:")) or "/" in rng:
        return "url"
    return "range"


def walk(repo: Path):
    for p in repo.rglob("*"):
        if not any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
            yield p


def find_manifests(repo: Path) -> list[Manifest]:
    found = []
    for p in walk(repo):
        rel = p.relative_to(repo).as_posix()
        if p.name == "package.json":
            found.append(Manifest(path=rel, kind="manifest", ecosystem="npm"))
        elif p.name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
            found.append(Manifest(path=rel, kind="lockfile", ecosystem="npm"))
        elif p.name.startswith("Dockerfile") or re.match(r"docker-compose.*\.ya?ml$", p.name):
            found.append(Manifest(path=rel, kind="container", ecosystem="docker"))
        elif rel.startswith(".github/workflows/") and p.suffix in (".yml", ".yaml"):
            found.append(Manifest(path=rel, kind="ci", ecosystem="github-actions"))
    return sorted(found, key=lambda m: (m.kind, m.path))


def npm_components(repo: Path) -> tuple[list[Component], list[str]]:
    lock = load_lock(repo)
    packages = lock["packages"]
    root = packages.get("", {})
    declared = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        declared.update(root.get(field) or {})

    comps = []
    for path, meta in packages.items():
        if not path or meta.get("link"):
            continue
        name = meta.get("name") or name_from_path(path)
        is_direct = path == f"node_modules/{name}" and name in declared
        scope = "dev" if meta.get("dev") else "optional" if meta.get("optional") else "prod"
        rng = declared.get(name) if is_direct else None
        comps.append(Component(
            name=name, version=meta.get("version", "unknown"), ecosystem="npm",
            direct=is_direct, scope=scope, lock_path=path, declared_range=rng,
            pinning=classify_npm_range(rng) if rng else "locked",
            resolved=meta.get("resolved"), integrity=meta.get("integrity"),
            has_install_script=bool(meta.get("hasInstallScript")),
            license=license_of(meta),
            source_file="package-lock.json",
        ))
    missing = sorted(n for n in declared if f"node_modules/{n}" not in packages)
    return comps, missing


def license_of(meta: dict):
    lic = meta.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if isinstance(lic, list):
        lic = " OR ".join(str(x.get("type", x)) if isinstance(x, dict) else str(x) for x in lic)
    return str(lic) if lic else None


def parse_image(ref: str) -> tuple[str, str, str]:
    if "@sha256:" in ref:
        name, digest = ref.split("@", 1)
        return name, digest, "digest"
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
        return name, tag, "tag (latest)" if tag == "latest" else "tag"
    return ref, "latest", "tag (implicit latest)"


def container_components(repo: Path, manifests: list[Manifest]) -> list[Component]:
    comps = []
    for m in manifests:
        if m.kind != "container":
            continue
        text = (repo / m.path).read_text(encoding="utf-8", errors="ignore")
        stages = set()
        if m.path.split("/")[-1].startswith("Dockerfile"):
            refs = []
            for line in text.splitlines():
                match = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
                if match:
                    if match.group(1) not in stages:
                        refs.append(match.group(1))
                    if match.group(2):
                        stages.add(match.group(2))
        else:
            refs = re.findall(r"^\s*image:\s*['\"]?([^\s'\"]+)", text, re.M)
        for ref in refs:
            name, version, pinning = parse_image(ref)
            comps.append(Component(name=name, version=version, ecosystem="docker",
                                   pinning=pinning, source_file=m.path, direct=True))
    return comps


def ci_components(repo: Path, manifests: list[Manifest]) -> list[Component]:
    comps = []
    for m in manifests:
        if m.kind != "ci":
            continue
        text = (repo / m.path).read_text(encoding="utf-8", errors="ignore")
        for ref in re.findall(r"uses:\s*['\"]?([^\s'\"#]+)", text):
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            name, version = ref.rsplit("@", 1)
            pinning = "sha" if SHA_RE.match(version) else "tag/branch"
            comps.append(Component(name=name, version=version, ecosystem="github-actions",
                                   pinning=pinning, source_file=m.path, direct=True))
    return comps


def git_commit(repo: Path):
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def discover(repo: Path, out_dir: Path) -> Inventory:
    pkg = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    manifests = find_manifests(repo)
    npm, missing = npm_components(repo)
    inv = Inventory(
        repo=str(repo), app_name=pkg.get("name", repo.name), app_version=pkg.get("version", ""),
        commit=git_commit(repo), manifests=manifests,
        components=npm + container_components(repo, manifests) + ci_components(repo, manifests),
        declared_not_locked=missing,
    )
    write_outputs(inv, out_dir)
    return inv


def write_outputs(inv: Inventory, out_dir: Path):
    npm = inv.npm()
    summary = {
        "total_components": len(inv.components),
        "npm_packages": len(npm),
        "unique_npm_name_versions": len({(c.name, c.version) for c in npm}),
        "direct": sum(c.direct for c in npm),
        "transitive": sum(not c.direct for c in npm),
        "prod": sum(c.scope == "prod" for c in npm),
        "dev": sum(c.scope == "dev" for c in npm),
        "container_images": sum(c.ecosystem == "docker" for c in inv.components),
        "ci_actions": sum(c.ecosystem == "github-actions" for c in inv.components),
        "packages_with_install_scripts": sum(c.has_install_script for c in npm),
    }
    (out_dir / "inventory.json").write_text(json.dumps(
        {"summary": summary, **inv.model_dump()}, indent=2), encoding="utf-8")
    deps = [{"name": c.name, "version": c.version, "ecosystem": c.ecosystem,
             "type": "direct" if c.direct else "transitive", "scope": c.scope,
             "declared_range": c.declared_range, "pinning": c.pinning,
             "lock_path": c.lock_path, "resolved": c.resolved,
             "has_install_script": c.has_install_script, "license": c.license} for c in npm]
    (out_dir / "dependency_inventory.json").write_text(json.dumps(
        {"repo": inv.repo, "lockfile": "package-lock.json", "summary": summary,
         "dependencies": deps}, indent=2), encoding="utf-8")
