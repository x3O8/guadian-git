import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from guardian.agents.discovery import SHA_RE, classify_npm_range, find_manifests, parse_image
from guardian.models import SuspiciousFinding

DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall",
             "uninstall", "postuninstall")
DANGEROUS = re.compile(r"curl|wget|https?://|\|\s*(?:ba)?sh|bash -c|eval|base64|node -e|powershell|nc ")
TRUSTED_REGISTRY = "registry.npmjs.org"
REMEDIATION = {
    "unexpected_dependency": "Confirm someone on the team added it on purpose and that it is the intended package. If not, remove it from package.json and the lockfile.",
    "suspicious_package_name": "Check the name letter by letter against the package you meant. Remove the look-alike, install the real one, and search the code for anything it touched.",
    "suspicious_version_change": "Find the commit and the reason for the change. Restore the previous version or a newer registry release, never a URL or git source, unless it is justified.",
    "lifecycle_script": "Do not install until reviewed. Read the script, remove it if it downloads or runs remote code, and install with --ignore-scripts in CI.",
    "lockfile_modified": "Delete the suspicious entry and regenerate the lockfile from the official registry (npm install --package-lock-only), then compare integrity hashes before merging.",
    "unpinned_container_image": "Pin the image by digest (image@sha256:...) so the same bytes are used every build, and update the digest deliberately.",
    "unexpected_ci_dependency": "Review the action's source, pin it to a full commit SHA, and give the workflow the minimum token permissions it needs.",
}


def git_show(repo: Path, ref: str, path: str):
    proc = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{path}"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.stdout if proc.returncode == 0 else None


def read(repo: Path, path: str):
    p = repo / path
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else None


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(name: str, known: set[str]):
    bare = name.split("/")[-1]
    hits = []
    for k in known:
        kb = k.split("/")[-1]
        dist = levenshtein(bare, kb)
        if k != name and len(kb) >= 4 and dist <= (1 if len(kb) < 6 else 2):
            hits.append((dist, k.startswith("@"), k))
    return min(hits)[2] if hits else None


def version_tuple(rng: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", rng or "")
    return tuple(map(int, m.groups())) if m else None


class Detector:
    def __init__(self, repo: Path, base_ref: str):
        self.repo, self.base_ref = repo, base_ref
        self.findings: list[SuspiciousFinding] = []
        self.notes: list[str] = []

    def add(self, **kw):
        kw.setdefault("remediation", REMEDIATION.get(kw.get("category"), ""))
        self.findings.append(SuspiciousFinding(id=f"SC-{len(self.findings) + 1:03d}", **kw))

    # ---------- git diff checks ----------
    def check_package_json(self, known_names: set[str]):
        old_raw, new_raw = git_show(self.repo, self.base_ref, "package.json"), read(self.repo, "package.json")
        if not old_raw or not new_raw:
            return
        old, new = json.loads(old_raw), json.loads(new_raw)
        for field in DEP_FIELDS:
            before, after = old.get(field) or {}, new.get(field) or {}
            for name, spec in after.items():
                if name not in before:
                    twin = lookalike(name, known_names)
                    self.add(category="unexpected_dependency", severity="high" if twin else "medium",
                             file="package.json", title=f"New {field} entry: {name}@{spec}",
                             before=None, after=f'"{name}": "{spec}"',
                             why_suspicious="Dependency added that is not in the baseline manifest."
                             + (f" Name is one or two edits away from existing package '{twin}' "
                                "(possible typosquat)." if twin else ""),
                             evidence={"field": field, "lookalike_of": twin, "base_ref": self.base_ref})
                    if twin:
                        self.add(category="suspicious_package_name", severity="high", file="package.json",
                                 title=f"Look-alike package name: {name} vs {twin}",
                                 before=twin, after=name,
                                 why_suspicious="Typosquatting: a near-identical name to a trusted package.",
                                 evidence={"edit_distance": levenshtein(name, twin)})
                elif before[name] != spec:
                    self.check_version_change(name, before[name], spec, field)

        old_s, new_s = old.get("scripts") or {}, new.get("scripts") or {}
        for hook in LIFECYCLE:
            if new_s.get(hook) and new_s.get(hook) != old_s.get(hook):
                risky = DANGEROUS.findall(new_s[hook])
                self.add(category="lifecycle_script", severity="critical" if risky else "high",
                         file="package.json", title=f"{'Changed' if hook in old_s else 'New'} '{hook}' script",
                         before=old_s.get(hook), after=new_s[hook],
                         why_suspicious="npm runs lifecycle scripts automatically on install. "
                         + (f"Script contains network/exec patterns: {sorted(set(risky))}." if risky else ""),
                         evidence={"hook": hook, "executed": False, "note": "script was statically inspected, never run"})

    def check_version_change(self, name, old_spec, new_spec, field):
        reasons = []
        if classify_npm_range(new_spec) == "url":
            reasons.append("spec now points to a URL/git source instead of the npm registry")
        if new_spec.strip() in ("*", "latest", ""):
            reasons.append("spec is now unbounded ('*'/'latest')")
        o, n = version_tuple(old_spec), version_tuple(new_spec)
        if o and n and n < o:
            reasons.append(f"version downgraded {'.'.join(map(str, o))} -> {'.'.join(map(str, n))}")
        if reasons:
            self.add(category="suspicious_version_change", severity="high", file="package.json",
                     title=f"Suspicious version change for {name}", before=f'"{name}": "{old_spec}"',
                     after=f'"{name}": "{new_spec}"', why_suspicious="; ".join(reasons),
                     evidence={"field": field})

    def check_lockfile(self):
        old_raw, new_raw = git_show(self.repo, self.base_ref, "package-lock.json"), read(self.repo, "package-lock.json")
        if not old_raw:
            self.notes.append(f"No package-lock.json at {self.base_ref}; lockfile diff skipped.")
            return
        if not new_raw:
            return
        old, new = json.loads(old_raw)["packages"], json.loads(new_raw)["packages"]
        for path, meta in new.items():
            if not path:
                continue
            prev = old.get(path)
            host = urlparse(meta.get("resolved", "")).hostname
            if prev is None:
                if host and host != TRUSTED_REGISTRY:
                    self.add(category="lockfile_modified", severity="high", file="package-lock.json",
                             title=f"New lockfile entry from untrusted host: {path}",
                             after=meta.get("resolved"), why_suspicious=f"Resolved from '{host}', not {TRUSTED_REGISTRY}.",
                             evidence={"lock_path": path, "version": meta.get("version")})
                if meta.get("hasInstallScript"):
                    self.add(category="lifecycle_script", severity="high", file="package-lock.json",
                             title=f"New package with install script: {path}",
                             after=f"hasInstallScript: true ({meta.get('version')})",
                             why_suspicious="A newly introduced package will run code during npm install.",
                             evidence={"lock_path": path})
                continue
            changed = {k: (prev.get(k), meta.get(k)) for k in ("version", "resolved", "integrity")
                       if prev.get(k) != meta.get(k)}
            if not changed:
                continue
            if "version" not in changed and ("integrity" in changed or "resolved" in changed):
                self.add(category="lockfile_modified", severity="critical", file="package-lock.json",
                         title=f"Integrity/source changed without a version change: {path}",
                         before=json.dumps({k: v[0] for k, v in changed.items()}),
                         after=json.dumps({k: v[1] for k, v in changed.items()}),
                         why_suspicious="Same version should always have the same tarball hash and source. "
                         "This is a classic sign of lockfile tampering.",
                         evidence={"lock_path": path, "version": meta.get("version"), "new_host": host})
            elif host and host != TRUSTED_REGISTRY:
                self.add(category="lockfile_modified", severity="high", file="package-lock.json",
                         title=f"Lockfile entry now resolves from '{host}': {path}",
                         before=prev.get("resolved"), after=meta.get("resolved"),
                         why_suspicious="Package source moved off the official npm registry.",
                         evidence={"lock_path": path})

    def check_dockerfiles(self, manifests):
        for m in manifests:
            if m.kind != "container" or not m.path.split("/")[-1].startswith("Dockerfile"):
                continue
            old, new = git_show(self.repo, self.base_ref, m.path), read(self.repo, m.path)
            if old is None or new is None or old == new:
                continue
            old_from = set(re.findall(r"^\s*FROM\s+(\S+)", old, re.M | re.I))
            for ref in re.findall(r"^\s*FROM\s+(\S+)", new, re.M | re.I):
                if ref in old_from:
                    continue
                _, version, pinning = parse_image(ref)
                if pinning != "digest":
                    self.add(category="unpinned_container_image", severity="high", file=m.path,
                             title=f"Base image changed to unpinned '{ref}'",
                             before=", ".join(sorted(old_from)), after=ref,
                             why_suspicious="Image is referenced by mutable tag, not @sha256 digest; "
                             "the content can change without any code change.",
                             evidence={"pinning": pinning})

    def baseline_actions(self) -> set[str]:
        proc = subprocess.run(["git", "-C", str(self.repo), "ls-tree", "-r", "--name-only", self.base_ref,
                               ".github/workflows"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        uses = set()
        for path in proc.stdout.split():
            uses |= set(re.findall(r"uses:\s*['\"]?([^\s'\"#]+)", git_show(self.repo, self.base_ref, path) or ""))
        return uses

    def check_workflows(self, manifests):
        trusted = self.baseline_actions()
        for m in manifests:
            if m.kind != "ci":
                continue
            old, new = git_show(self.repo, self.base_ref, m.path) or "", read(self.repo, m.path) or ""
            if old == new:
                continue
            for ref in re.findall(r"uses:\s*['\"]?([^\s'\"#]+)", new):
                if ref in trusted or ref.startswith("./"):
                    continue
                pinned = "@" in ref and SHA_RE.match(ref.rsplit("@", 1)[1])
                self.add(category="unexpected_ci_dependency", severity="medium" if pinned else "high",
                         file=m.path, title=f"New CI action: {ref}", after=ref,
                         why_suspicious="New third-party code runs in CI with repository secrets/tokens."
                         + ("" if pinned else " It is pinned to a mutable branch/tag, not a commit SHA."),
                         evidence={"new_file": not old})
            new_runs = set(re.findall(r"run:\s*(.+)", new)) - set(re.findall(r"run:\s*(.+)", old))
            for run in new_runs:
                if DANGEROUS.search(run):
                    self.add(category="unexpected_ci_dependency", severity="high", file=m.path,
                             title="New CI step downloads/executes remote code", after=run.strip(),
                             why_suspicious="Pipes remote content into a shell inside CI.", evidence={})

    # ---------- static posture checks on the current tree ----------
    def baseline_checks(self, inventory):
        for c in inventory.components:
            if c.ecosystem == "docker" and c.pinning != "digest":
                self.add(kind="baseline", category="unpinned_container_image", severity="medium",
                         file=c.source_file, title=f"Container image not digest-pinned: {c.name}:{c.version}",
                         after=f"{c.name}:{c.version}",
                         why_suspicious="Mutable tags can be repointed upstream.", evidence={"pinning": c.pinning})
        unpinned_actions = sorted({f"{c.name}@{c.version}" for c in inventory.components
                                   if c.ecosystem == "github-actions" and c.pinning != "sha"})
        if unpinned_actions:
            self.add(kind="baseline", category="unexpected_ci_dependency", severity="low",
                     file=".github/workflows", title=f"{len(unpinned_actions)} CI actions not SHA-pinned",
                     why_suspicious="Tag-pinned actions can be changed by their owners.",
                     evidence={"actions": unpinned_actions})
        scripts = sorted(f"{c.name}@{c.version}" for c in inventory.npm() if c.has_install_script)
        if scripts:
            self.add(kind="baseline", category="lifecycle_script", severity="info", file="package-lock.json",
                     title=f"{len(scripts)} dependencies declare install scripts",
                     why_suspicious="Inventory of packages that execute code at install time (review list).",
                     evidence={"packages": scripts})
        off_registry = sorted(f"{c.lock_path} -> {c.resolved}" for c in inventory.npm()
                              if c.resolved and urlparse(c.resolved).hostname != TRUSTED_REGISTRY)
        if off_registry:
            self.add(kind="baseline", category="lockfile_modified", severity="medium", file="package-lock.json",
                     title=f"{len(off_registry)} lockfile entries resolve outside {TRUSTED_REGISTRY}",
                     why_suspicious="Non-registry sources bypass registry integrity guarantees.",
                     evidence={"entries": off_registry[:50]})
        if inventory.declared_not_locked:
            self.add(kind="baseline", category="lockfile_modified", severity="medium", file="package.json",
                     title="Declared dependencies missing from lockfile",
                     why_suspicious="Manifest and lockfile are out of sync.",
                     evidence={"packages": inventory.declared_not_locked})


def detect(repo: Path, out_dir: Path, inventory, base_ref: str = "HEAD"):
    d = Detector(repo, base_ref)
    manifests = find_manifests(repo)
    base_lock = git_show(repo, base_ref, "package-lock.json")
    known = {c.name for c in inventory.npm()}
    if base_lock:
        known = {p.rsplit("node_modules/", 1)[-1] for p in json.loads(base_lock)["packages"] if p}
    base_pkg = git_show(repo, base_ref, "package.json")
    if base_pkg:
        declared = json.loads(base_pkg)
        known |= {n for f in DEP_FIELDS for n in (declared.get(f) or {})}
    d.check_package_json(known)
    d.check_lockfile()
    d.check_dockerfiles(manifests)
    d.check_workflows(manifests)
    d.baseline_checks(inventory)
    data = {"repo": str(repo), "base_ref": base_ref,
            "change_findings": sum(f.kind == "change" for f in d.findings),
            "baseline_findings": sum(f.kind == "baseline" for f in d.findings),
            "notes": d.notes, "findings": [f.model_dump() for f in d.findings]}
    (out_dir / "suspicious_changes.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    return d.findings, d.notes
