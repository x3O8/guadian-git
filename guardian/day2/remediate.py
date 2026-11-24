"""Agent 7 - Remediation.

Turns prioritised risks and investigations into concrete, reviewable change requests:
upgrade to a safe version, upgrade the parent that pulls it in, pin a trusted version (npm overrides),
replace or remove, update/pin the container base image, pin CI actions, block or disable an unsafe install
step, or escalate for security review.

Each action states the exact file changes, the expected risk reduction, the compatibility impact and the
rollback. Nothing is applied here: actions wait for a human decision (approvals.py) and are then
validated in a sandbox (validate.py).
"""
import hashlib
import json
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

from guardian import analysis
from guardian.day2 import reachability
from guardian.day2.common import day2_dir, write_json
from guardian.models import Change, RemediationAction
from guardian.recommend import npm_fixes, vtuple

SEV = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]
TIER_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def action_hash(a: dict) -> str:
    """Identity of an action for approvals: what it changes, not how it is described."""
    body = {"type": a["type"], "changes": a.get("changes", []), "covers": sorted(a.get("covers_packages", []))}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def jump(cur: str, new: str) -> str:
    a, b = vtuple(cur), vtuple(new)
    if not a or not b:
        return "unknown"
    if b < a:
        return "downgrade"
    if a[0] != b[0] or (a[0] == 0 and a[:2] != b[:2]):
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


def keep_prefix(old_range: str, version: str) -> str:
    old = (old_range or "").strip()
    simple = re.fullmatch(r"[\^~]?\d[\w.\-+]*", old)
    return (old[0] + version) if simple and old[:1] in ("^", "~") else version


def manifest_section(manifest: dict, name: str):
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (manifest.get(sec) or {}):
            return sec, manifest[sec][name]
    return None, None


def parent_range(lock: dict, child: str, parent_name: str):
    for path, entry in lock.get("packages", {}).items():
        if path.endswith("node_modules/" + parent_name):
            for sec in ("dependencies", "optionalDependencies", "peerDependencies"):
                if child in (entry.get(sec) or {}):
                    return entry[sec][child]
    return None


# ---------------- external lookups for pinning (read-only, optional) ----------------
def _get(url, headers=None, method="GET", timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "software-supply-chain-guardian/2.0", **(headers or {})}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.headers, r.read()


def image_digest(image: str, tag: str):
    """Resolve a Docker Hub tag to its manifest digest. Returns None when offline or not Docker Hub."""
    if "." in image.split("/")[0] and not image.startswith("docker.io/"):
        return None  # other registries (gcr.io, ghcr.io) need their own auth flow
    repo = image.removeprefix("docker.io/")
    repo = repo if "/" in repo else f"library/{repo}"
    try:
        _, body = _get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")
        token = json.loads(body)["token"]
        h, _ = _get(f"https://registry-1.docker.io/v2/{repo}/manifests/{urllib.parse.quote(tag)}", method="HEAD", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
                      "application/vnd.docker.distribution.manifest.v2+json"})
        return h.get("Docker-Content-Digest")
    except Exception:
        return None


def action_sha(action: str, ref: str):
    owner_repo = "/".join(action.split("/")[:2])
    try:
        _, body = _get(f"https://api.github.com/repos/{owner_repo}/commits/{urllib.parse.quote(ref)}",
                       headers={"Accept": "application/vnd.github+json"})
        return json.loads(body)["sha"]
    except Exception:
        return None


# ---------------- plan ----------------
def plan(repo: Path, d1: dict, risks: dict, invs: dict, use_llm: bool = True, resolve_pins: bool = True) -> dict:
    out, repo = d1["out"], Path(repo)
    manifest = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((repo / "package-lock.json").read_text(encoding="utf-8"))
    fixes = npm_fixes(out / "raw")
    recs = {(r["package"], r["installed_version"]): r for r in d1["recs"]}
    findings = d1["vulns"]["findings"]
    imports = reachability.scan_imports(repo)
    risk_by_pkg = {(i["package"], i["version"]): i for i in risks["items"] if i["kind"] == "vulnerability"}

    def lockver(n):
        return lock.get("packages", {}).get("node_modules/" + n, {}).get("version")

    def parent_fix(dname):
        pf = fixes.get(dname)
        if isinstance(pf, dict) and pf.get("name") == dname and manifest_section(manifest, dname)[0] \
                and jump(lockver(dname) or "0", pf["version"]) != "downgrade":
            return ("set", dname, pf["version"])
        return None

    # 1. for every vulnerable copy, the set of changes that removes it from the tree
    needs = []  # (instance, risk, frozenset(keys), note)
    for (pkg, ver), risk in risk_by_pkg.items():
        rec = recs.get((pkg, ver), {})
        need = rec.get("fixed_in")
        direct = rec.get("direct", risk["evidence"]["direct"])
        via = rec.get("introduced_via", risk["evidence"]["introduced_via"])
        via_names = [v.rsplit("@", 1)[0] if "@" in v[1:] else v for v in via]
        fa = fixes.get(pkg)
        keys, note = None, ""
        if fa is False:
            keys = {("replace-remove", pkg, None)}
        elif direct:
            if isinstance(fa, dict) and fa.get("name") == pkg and jump(ver, fa["version"]) != "downgrade":
                keys = {("set", pkg, fa["version"])}
            elif need:
                keys = {("set", pkg, need)}
                if isinstance(fa, dict) and jump(ver, fa.get("version", "0")) == "downgrade":
                    note = f"npm audit's automatic fix would downgrade {pkg} to {fa['version']}; upgrading to {need} instead."
        else:
            # every direct dependency that pulls this copy in must move, otherwise the copy stays
            pf = [parent_fix(d) for d in via_names]
            if via_names and all(pf):
                keys = set(pf)
            elif need:
                keys = {("override", pkg, need)}
                blocked = [d for d, f in zip(via_names, pf) if not f]
                if blocked:
                    note = (f"{', '.join(blocked)} {'has' if len(blocked) == 1 else 'have'} no safe upgrade that drops {pkg} {ver} (npm audit would downgrade it), "
                            f"so {pkg} is pinned to {need} with npm overrides instead.")
            elif isinstance(fa, dict) and vtuple(fa.get("version")) > vtuple(ver) and fa.get("name") == pkg:
                keys = {("override", pkg, fa["version"])}
        if not keys:
            keys = {("escalate", pkg, None)}
        needs.append((f"{pkg}@{ver}", risk, frozenset(keys), note))

    # 2. copies that share a change are fixed by one action (e.g. jws needs both jsonwebtoken and express-jwt)
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for _, _, keys, _ in needs:
        ks = sorted(keys, key=str)
        for k in ks[1:]:
            parent[find(k)] = find(ks[0])
        find(ks[0])
    groups = defaultdict(lambda: {"packages": [], "risks": [], "notes": [], "keys": set()})
    for inst, risk, keys, note in needs:
        g = groups[find(sorted(keys, key=str)[0])]
        g["packages"].append(inst)
        g["risks"].append(risk)
        g["keys"] |= set(keys)
        if note:
            g["notes"].append(note)

    actions = []
    for g in groups.values():
        covered = {tuple(p.rsplit("@", 1)) for p in g["packages"]}
        cleared = [f for f in findings if (f["package"], f["installed_version"]) in covered]
        sev_counts = {s: sum(1 for f in cleared if f["severity"] == s) for s in SEV if any(f["severity"] == s for f in cleared)}
        keys = sorted(g["keys"], key=lambda k: (k[0] != "set", k[1]))
        changes, parts, compat_rows, auto = [], [], [], True
        for op, name, version in keys:
            sec, rng = manifest_section(manifest, name)
            used_in = (imports.get(name) or {}).get("runtime", [])
            if op == "set":
                cur = lockver(name) or (rng or "").lstrip("^~=")
                j = jump(cur, version)
                changes.append(Change(file="package.json", op="set-dependency", target=name, value=keep_prefix(rng, version), section=sec))
                parts.append(f"{name} {cur} → {version}")
                compat_rows.append(("High" if j == "major" and used_in else "Medium" if j == "major" else "Low", j, name, cur, version, used_in))
            elif op == "override":
                via0 = next((r["evidence"]["introduced_via"] for r in g["risks"] if r["package"] == name), []) or ["?"]
                pname = via0[0].rsplit("@", 1)[0] if "@" in via0[0][1:] else via0[0]
                asked = parent_range(lock, name, pname)
                changes.append(Change(file="package.json", op="add-override", target=name, value=version, section="overrides"))
                parts.append(f"pin {name} {version}")
                compat_rows.append(("Medium", "override", name, asked, version, []))
            else:
                auto = False
        names_changed = {k[1] for k in keys}
        others = sorted({p.rsplit("@", 1)[0] for p in g["packages"]} - names_changed)
        if not auto:
            op, name, _ = keys[0]
            used_in = (imports.get(name) or {}).get("runtime", [])
            typ = "replace-remove" if op == "replace-remove" else "escalate"
            title = f"Replace or remove {name} (no fixed version exists)" if typ == "replace-remove" else f"Escalate {name} for security review"
            compat = {"level": "High" if typ == "replace-remove" else "Unknown", "semver": "replacement" if typ == "replace-remove" else "n/a",
                      "files_using": used_in[:10],
                      "summary": (f"No patched {name} has been published. Replacing it means code changes"
                                  + (f" in {', '.join(used_in[:4])}." if used_in else ".")) if typ == "replace-remove" else "No safe automatic fix.",
                      "check": "Pick a maintained alternative, or isolate the code path and accept the risk with a review date."}
        else:
            only_override = all(k[0] == "override" for k in keys)
            typ = "pin-override" if only_override else ("upgrade" if any(n in names_changed for n, _ in covered) else "upgrade-parent")
            verb = "Pin" if only_override else "Upgrade"
            title = (f"Pin {keys[0][1]} to {keys[0][2]} with npm overrides" if only_override and len(keys) == 1
                     else f"{verb} " + " and ".join(p.replace("pin ", "") if not only_override else p for p in parts))
            if others:
                title += f" (also clears {', '.join(others)})"
            rank = {"High": 0, "Medium": 1, "Low": 2}
            level = min((r[0] for r in compat_rows), key=lambda x: rank.get(x, 9))
            files = sorted({f for r in compat_rows for f in r[5]})
            summary = []
            for lvl, j, name, cur, version, used_in in compat_rows:
                if j == "override":
                    summary.append(f"Forces every copy of {name} to {version}" + (f" although its parent asks for \"{cur}\"" if cur else "")
                                   + "; the parent may rely on the old behaviour.")
                else:
                    summary.append(f"{name}: {j} version jump" + (f", imported by application code in {len(used_in)} file(s)"
                                                                  f" ({', '.join(used_in[:3])})" if used_in else ", not imported directly by application code") + ".")
            compat = {"level": level, "semver": ", ".join(sorted({r[1] for r in compat_rows})), "files_using": files[:10],
                      "summary": " ".join(summary),
                      "check": "Read the changelogs of " + ", ".join(sorted(names_changed)) + " for breaking changes; the sandbox build and tests show what actually breaks."}
        actions.append(RemediationAction(
            id="", type=typ, title=title, covers_packages=sorted(g["packages"]),
            covers_risks=sorted(r["id"] for r in g["risks"]), advisories_cleared=len(cleared), severity_cleared=sev_counts,
            changes=changes, auto_applicable=auto, compatibility=compat,
            rationale=" ".join(g["notes"]) or "", priority=min((r["tier"] for r in g["risks"]), key=lambda t: TIER_RANK.get(t, 9)),
            confidence=round(min(r["confidence"] for r in g["risks"]) * (0.95 if typ == "pin-override" else 1.0), 2)))

    # ---- supply-chain (non-CVE) actions from the investigation ----
    for inv in invs["items"]:
        if inv["verdict"] == "Expected":
            continue
        cat = inv["category"]
        if cat == "install-script" and "telemetry" in inv["title"] and "scarf" in inv["subject"].lower():
            actions.append(RemediationAction(
                id="", type="harden-config", title="Turn off Scarf install telemetry", covers_packages=[inv["subject"]],
                covers_risks=[inv["id"]], changes=[Change(file="package.json", op="set-json", target="scarfSettings.enabled", value="false")],
                auto_applicable=True, priority="Medium", confidence=0.9,
                compatibility={"level": "Low", "semver": "config", "files_using": [],
                               "summary": "Only stops the install-time analytics call; no application code changes.",
                               "check": "None beyond a normal install."}))
        elif cat == "unpinned_container_image":
            changes, missing = [], []
            for fact in inv["verified_evidence"]:
                ref = fact["fact"].split(" (")[0]
                image, _, tag = ref.rpartition(":") if ":" in ref.split("/")[-1] else (ref, "", "latest")
                digest = image_digest(image, tag) if resolve_pins else None
                if digest and (repo / fact["source"]).exists():
                    changes.append(Change(file=fact["source"], op="replace-text", target=ref, value=f"{ref}@{digest}"))
                else:
                    missing.append(ref)
            actions.append(RemediationAction(
                id="", type="update-base-image", title=f"Pin {len(changes) or len(missing)} container image(s) by digest",
                covers_packages=[], covers_risks=[inv["id"]], changes=changes, auto_applicable=bool(changes),
                priority="Medium", confidence=0.8 if changes else 0.6,
                rationale="" if not missing else f"Digest could not be looked up for: {', '.join(missing[:6])}. "
                                                  "Run `docker buildx imagetools inspect <image>` and add @sha256:<digest> by hand.",
                compatibility={"level": "Low", "semver": "pin", "files_using": [],
                               "summary": "Same image as today, but frozen: future base-image security patches need a deliberate digest update.",
                               "check": "Rebuild the container; schedule digest refreshes (e.g. Renovate/Dependabot)."}))
        elif cat == "unexpected_ci_dependency":
            refs = [a.strip() for f in inv["verified_evidence"][1:] for a in f["fact"].split(",") if "@" in a]
            changes, missing = [], []
            wf_dir = repo / ".github" / "workflows"
            for ref in refs:
                action, _, tag = ref.rpartition("@")
                sha = action_sha(action, tag) if resolve_pins else None
                files = [p for p in wf_dir.glob("*.y*ml") if f"{action}@{tag}" in p.read_text(encoding="utf-8", errors="replace")] if wf_dir.exists() else []
                if sha and files:
                    for p in files:
                        changes.append(Change(file=p.relative_to(repo).as_posix(), op="replace-text", target=f"{action}@{tag}", value=f"{action}@{sha} # {tag}"))
                else:
                    missing.append(ref)
            actions.append(RemediationAction(
                id="", type="pin-action", title=f"Pin {len(refs)} CI action(s) to a commit SHA", covers_risks=[inv["id"]],
                changes=changes, auto_applicable=bool(changes), priority="Low", confidence=0.85 if changes else 0.6,
                rationale="" if not missing else f"SHA lookup unavailable for: {', '.join(missing[:7])}. Pin by hand from each action's release page.",
                compatibility={"level": "Low", "semver": "pin", "files_using": [],
                               "summary": "Runs the exact same action code as today, but it can no longer change underneath you.",
                               "check": "Let a bot (Dependabot) propose SHA updates."}))
        elif cat == "install-script":
            actions.append(RemediationAction(
                id="", type="escalate", title=f"Security review: install script in {inv['subject']}", covers_packages=[inv["subject"]],
                covers_risks=[inv["id"]], auto_applicable=False, priority="Low", confidence=0.7, rationale=inv["remedy"],
                compatibility={"level": "Unknown", "semver": "n/a", "files_using": [],
                               "summary": "Blocking scripts globally (--ignore-scripts) would also stop native modules like sqlite3 from building.",
                               "check": "Decide per package: allow, disable or replace."}))
        elif inv["verdict"] == "Suspicious" and inv.get("day1_ref"):
            base = d1["suspicious"].get("base_ref", "HEAD")
            actions.append(RemediationAction(
                id="", type="block", title=f"Block: revert {inv['subject']} to {base}", covers_risks=[inv["id"]],
                changes=[Change(file=inv["subject"], op="restore-file", target=inv["subject"], value=base)],
                auto_applicable=True, priority="High", confidence=0.8, rationale=inv["remedy"],
                compatibility={"level": "Medium", "semver": "revert", "files_using": [],
                               "summary": f"Restores {inv['subject']} exactly as it was at {base}; any legitimate change in that file is undone too.",
                               "check": "Confirm with the author of the change."}))

    # ---- expected risk reduction (projected; validation measures the real one) ----
    changes_d1 = [f for f in d1["suspicious"]["findings"] if f["kind"] == "change"]
    s0, g0, _, _ = analysis.risk_grade(findings, changes_d1, d1["inventory"])
    risk_total = sum(i["score"] for i in risks["items"])
    risk_scores = {i["id"]: i["score"] for i in risks["items"]}
    inv_risk = {i["evidence"].get("investigation"): i for i in risks["items"] if i["kind"] == "supply-chain"}
    for a in actions:  # link non-CVE actions to their risk entries
        a.covers_risks = sorted({inv_risk[r]["id"] if r in inv_risk else r for r in a.covers_risks})
        if a.type in ("harden-config", "update-base-image", "pin-action", "escalate", "block"):
            tiers = [inv_risk[r]["tier"] for r in inv_risk if inv_risk[r]["id"] in a.covers_risks]
            if tiers:
                a.priority = min(tiers, key=lambda t: TIER_RANK.get(t, 9))
    tier_rank = TIER_RANK
    for a in actions:
        covered = {tuple(p.rsplit("@", 1)) for p in a.covers_packages if a.type not in ("harden-config", "escalate")}
        remaining = [f for f in findings if (f["package"], f["installed_version"]) not in covered] if a.auto_applicable else findings
        s1, g1, _, _ = analysis.risk_grade(remaining, changes_d1, d1["inventory"])
        pts = sum(risk_scores.get(r, 0) for r in a.covers_risks) if a.auto_applicable else 0
        a.expected_risk_reduction = {
            "advisories_cleared": a.advisories_cleared if a.auto_applicable else 0,
            "risk_points_removed": round(pts, 1), "risk_points_total": round(risk_total, 1),
            "grade_before": f"{g0} ({s0})", "grade_after_projected": f"{g1} ({s1})",
            "statement": (f"Clears {a.advisories_cleared} advisor{'y' if a.advisories_cleared == 1 else 'ies'} "
                          f"({', '.join(f'{n} {s}' for s, n in a.severity_cleared.items())}) in {len(a.covers_packages)} package(s). "
                          + (f"projected grade {g0} ({s0}) → {g1} ({s1}). " if (g0, s0) != (g1, s1) else "")
                          + "To be confirmed by the sandbox rescan.")
            if a.advisories_cleared and a.auto_applicable else
            ("Removes a non-CVE supply-chain risk; the rescan confirms the finding disappears." if a.auto_applicable else
             "No automatic change: risk only goes down once a human replaces, removes or accepts it.")}
        a.rollback = ("Tested on its own branch in a sandbox copy; your working copy is untouched. "
                      "If merged later, undo it with git revert on the fix commit (its id is recorded after validation), or restore "
                      + ", ".join(sorted({c.file for c in a.changes}) or ["the files"]) + " from the baseline commit.") if a.auto_applicable \
            else "Nothing is changed automatically, so there is nothing to roll back."

    actions.sort(key=lambda a: (not a.auto_applicable, tier_rank.get(a.priority, 9), -a.expected_risk_reduction.get("risk_points_removed", 0), a.title))
    for k, a in enumerate(actions, 1):
        a.id = f"ACT-{k:03d}"

    if use_llm:
        from guardian.day2 import reasoning
        res = reasoning.explain(out, "For each remediation action explain in plain words why this is the right fix, what "
                                     "could break (use the compatibility data) and what the reviewer should check before "
                                     "approving. Mention the expected risk reduction.",
                                [{"id": a.id, "evidence": {"title": a.title, "type": a.type, "packages": a.covers_packages,
                                                           "changes": [c.model_dump() for c in a.changes],
                                                           "compatibility": a.compatibility,
                                                           "expected_risk_reduction": a.expected_risk_reduction,
                                                           "note": a.rationale}} for a in actions],
                                {a.id: "" for a in actions})
        for a in actions:
            if res[a.id]["source"].startswith("AI"):
                a.rationale = (a.rationale + " " if a.rationale else "") + res[a.id]["text"]
                a.rationale_source = res[a.id]["source"]
    for a in actions:
        if not a.rationale_source:
            a.rationale_source = "rule-based"

    data = {"actions": [], "baseline": {"grade": f"{g0} ({s0})", "risk_points_total": round(risk_total, 1),
                                        "advisories": len(findings)}}
    for a in actions:
        d = a.model_dump()
        d["hash"] = action_hash(d)
        data["actions"].append(d)
    write_json(day2_dir(out) / "remediation_plan.json", data)
    return data
