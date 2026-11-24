"""Per-package fix recommendations, built only from scanner data.

Sources: the vulnerability findings (fixed versions, paths, scope) and, when npm audit was used,
its own `fixAvailable` field (which package to change, to which version, and whether that is a
semver-major jump). Nothing here is applied automatically.
"""
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

SEV = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]


def vtuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:3]) if nums else ()


def npm_fixes(raw_dir: Path) -> dict:
    p = raw_dir / "npm-audit.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    return {name: e.get("fixAvailable") for name, e in data.get("vulnerabilities", {}).items()}


def headline_for(kind, pkg, ver, fa, installed, via, need, fixes, direct) -> str:
    if kind == "No patch published":
        return f"No patched {pkg} exists. Replace or remove it"
    if isinstance(fa, dict):
        target, tver = fa.get("name"), fa.get("version")
        current = installed.get(target)
        major = " (major)" if fa.get("isSemVerMajor") else ""
        if kind == "Upgrade the package" and current and vtuple(tver) < vtuple(current) and need:
            return f"Upgrade {pkg} {ver} → {need}"
        if kind == "No safe automatic fix":
            return f"Pin {pkg} to {need} or later via overrides" if need else f"Wait for a fixed {target}"
        if target == pkg and not direct:
            pname, _, pver = via[0].rpartition("@") if via else ("its parent", "", "")
            pf = fixes.get(pname)
            if isinstance(pf, dict) and pf.get("name") == pname:
                return f"Upgrade {pname} {pver} → {pf['version']}" + (" (major)" if pf.get("isSemVerMajor") else "")
            return f"Upgrade {pname} so it uses {pkg} {need or tver}+"
        return f"Upgrade {target} {current or ver} → {tver}{major}"
    if need and direct:
        return f"Upgrade {pkg} {ver} → {need}"
    if need:
        return f"Upgrade {', '.join(via[:1])} or pin {pkg} {need}+"
    return f"Replace or remove {pkg}"


def priority(worst: str, scope: str) -> str:
    shipped = scope == "prod"
    if worst in ("critical", "high") and shipped:
        return "P1 — fix first"
    if shipped or worst in ("critical", "high"):
        return "P2 — fix soon"
    return "P3 — plan"


def recommend(findings: list, deps: list, raw_dir: Path) -> list[dict]:
    installed = {d["name"]: d["version"] for d in deps if d.get("type") == "direct"}
    fixes = npm_fixes(raw_dir)
    groups = defaultdict(list)
    for f in findings:
        groups[(f["package"], f["installed_version"])].append(f)
    recs = []
    for (pkg, ver), items in groups.items():
        worst = min((i["severity"] for i in items), key=lambda s: SEV.index(s) if s in SEV else 9)
        scope = "prod" if any(i["scope"] == "prod" for i in items) else items[0]["scope"]
        direct = any(i["direct"] for i in items)
        via = sorted({v for i in items for v in i.get("introduced_via", [])})
        fixed = sorted({i["fixed_version"] for i in items if i.get("fixed_version")}, key=vtuple)
        need = fixed[-1] if fixed else None
        fa = fixes.get(pkg)
        steps, kind = [], None

        if isinstance(fa, dict):
            target, tver, major = fa.get("name"), fa.get("version"), bool(fa.get("isSemVerMajor"))
            current = installed.get(target)
            downgrade = current and vtuple(tver) < vtuple(current)
            if downgrade and target == pkg and direct and need:
                kind = "Upgrade the package"
                steps.append(f"Upgrade {pkg} from {ver} to {need} or later in package.json. npm audit only offers a "
                             f"downgrade to {tver}, which would undo other fixes.")
            elif downgrade:
                kind = "No safe automatic fix"
                steps.append(f"npm audit's only automatic fix is downgrading {target} from {current} to {tver}. Don't do that: it rolls back other fixes.")
                if need:
                    steps.append(f"Force {pkg} to {need} or later with an \"overrides\" entry in package.json, then run the tests.")
                steps.append(f"Watch for a {target} release that depends on a fixed {pkg}.")
            elif target == pkg and not direct:
                kind = "Upgrade the parent"
                for parent in via[:2]:
                    pname, _, pver = parent.rpartition("@")
                    pf = fixes.get(pname)
                    if isinstance(pf, dict) and pf.get("name") == pname and vtuple(pf.get("version")) > vtuple(pver):
                        steps.append(f"This copy of {pkg} ({ver}) comes from {pname}. Upgrade {pname} from {pver} to "
                                     f"{pf['version']}, which no longer uses the vulnerable version"
                                     + (" (major version: test carefully)." if pf.get("isSemVerMajor") else "."))
                    else:
                        steps.append(f"This copy of {pkg} ({ver}) comes from {pname} {pver}. Upgrade {pname} to a release "
                                     f"that depends on {pkg} {need or tver} or later.")
                if need or tver:
                    steps.append(f"Or force {pkg} to {need or tver} or later with an \"overrides\" entry in package.json.")
            elif target == pkg:
                kind = "Upgrade the package"
                steps.append(f"Upgrade {pkg} from {ver} to {tver} in package.json" + (" (major version: check its changelog for breaking changes)." if major else "."))
            else:
                kind = "Upgrade the parent"
                steps.append(f"Upgrade {target} from {current or 'its current version'} to {tver}; that release no longer pulls in a vulnerable {pkg}"
                             + (" (major version: test carefully)." if major else "."))
                if need:
                    steps.append(f"If {target} can't move yet, force {pkg} to {need} or later with an \"overrides\" entry.")
        elif fa is False:
            kind = "No patch published"
            steps.append(f"No fixed version of {pkg} exists for these advisories.")
            steps.append(f"Replace {pkg} with a maintained alternative, or remove it" + (" (it's listed in package.json)." if direct else f" by changing what pulls it in ({', '.join(via[:2])})."))
            steps.append("Until then, keep untrusted input away from the affected functions described in the advisories.")
        else:  # OSV mode or no npm data: use the advisory's fixed version
            if need and direct:
                kind = "Upgrade the package"
                steps.append(f"Upgrade {pkg} from {ver} to {need} or later in package.json.")
            elif need:
                kind = "Upgrade the parent"
                steps.append(f"Upgrade {', '.join(via[:2])} to a release that depends on {pkg} {need} or later.")
                steps.append(f"Or force {pkg} to {need} or later with an \"overrides\" entry in package.json.")
            else:
                kind = "No patch published"
                steps.append(f"No fixed version is listed. Replace or remove {pkg}, or isolate the code that uses it.")
        if not need and isinstance(fa, dict) and fa.get("name") == pkg and vtuple(fa.get("version")) > vtuple(ver):
            need = fa.get("version")
        if scope == "dev":
            steps.append("Dev-only: it isn't shipped to users, so this is lower priority.")
        headline = headline_for(kind, pkg, ver, fa, installed, via, need, fixes, direct)
        recs.append({
            "package": pkg, "installed_version": ver, "worst_severity": worst, "advisories": len(items),
            "ids": sorted({i["id"] for i in items}), "scope": scope, "direct": direct, "introduced_via": via,
            "fixed_in": need, "action": kind, "headline": headline, "priority": priority(worst, scope), "steps": steps,
            "source": "npm audit fixAvailable + advisory data" if fa is not None else "advisory fixed versions",
        })
    recs.sort(key=lambda r: (r["priority"], SEV.index(r["worst_severity"]) if r["worst_severity"] in SEV else 9, r["package"]))
    return recs


def write(out_dir: Path, recs: list):
    (out_dir / "fix_recommendations.json").write_text(json.dumps(recs, indent=2), encoding="utf-8")
    with open(out_dir / "fix_recommendations.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["priority", "package", "installed", "worst severity", "advisories", "scope", "how it got in",
                    "action", "fixed in", "steps", "advisory ids"])
        for r in recs:
            w.writerow([r["priority"], r["package"], r["installed_version"], r["worst_severity"], r["advisories"],
                        r["scope"], "direct" if r["direct"] else ", ".join(r["introduced_via"]), r["action"],
                        r["fixed_in"] or "", " ".join(r["steps"]), " ".join(r["ids"])])
