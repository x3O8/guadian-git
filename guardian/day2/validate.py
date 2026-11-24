"""Agent 8 - Validation & Report, part 1: validation (test before you trust).

For every action a human approved:
  1. create a throwaway git worktree on its own branch (guardian/<run>-<action>) next to, not inside, your copy
  2. commit a baseline snapshot, apply the change, regenerate the lockfile (--ignore-scripts), commit the fix
  3. install with `npm ci --ignore-scripts`, build, run the unit tests, and load each changed package once
  4. rescan the result with the Day 1 agents (SBOM, graph, vulnerabilities, anomalies)
  5. compare with an untouched baseline run: SBOM before/after, advisories resolved and newly introduced,
     new dependencies, build and test regressions
The same is done once more with every action that passed, together (the release candidate).

Dependency install scripts never run. The application's own build and tests do run, inside the sandbox,
because that is what validating a fix means; the reviewer approved exactly that.
Nothing is merged or pushed: the branch and a .patch file are left for a human.
"""
import json
import os
import re
import shlex
import shutil
from datetime import datetime
from pathlib import Path

from guardian.day2.common import SANDBOX, audit, day2_dir, read_json, run, tool, write_json
from guardian.repo_fetch import remove_tree

SEV = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]


# ---------------- what to run ----------------
def profile(repo: Path) -> dict:
    pkg = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    scripts = pkg.get("scripts", {})
    npm, npx = tool("npm"), tool("npx")
    build = None
    if os.getenv("GUARDIAN_BUILD_CMD"):
        build = shlex.split(os.getenv("GUARDIAN_BUILD_CMD"))
    else:
        for s in ("build:server", "build:backend", "compile", "build"):
            if s in scripts:
                build = [npm, "run", s]
                break
        if build is None and (repo / "tsconfig.json").exists():
            build = [npx, "--no-install", "tsc", "--noEmit", "-p", "."]
    test = None
    if os.getenv("GUARDIAN_TEST_CMD"):
        test = shlex.split(os.getenv("GUARDIAN_TEST_CMD"))
    else:
        for s in ("test:server", "test:unit", "test"):
            cmd = scripts.get(s, "")
            if cmd and "no test specified" not in cmd and not re.search(r"cypress|playwright|protractor|karma", cmd):
                test = [npm, "run", s]
                break
    return {"install": [npm, "ci", "--ignore-scripts"], "build": build, "test": test}


def parse_tests(text: str) -> dict:
    t = {"passed": None, "failed": None, "skipped": None, "failing": []}
    m = re.search(r"^# pass (\d+)", text, re.M)
    if m:  # node:test (TAP)
        t["passed"] = int(m.group(1))
        t["failed"] = int(re.search(r"^# fail (\d+)", text, re.M).group(1)) if re.search(r"^# fail (\d+)", text, re.M) else 0
        sk = re.search(r"^# skipped (\d+)", text, re.M)
        t["skipped"] = int(sk.group(1)) if sk else 0
        t["failing"] = sorted(set(re.findall(r"^\s*not ok \d+ - (.+)$", text, re.M)))[:50]
        return t
    m = re.search(r"(\d+) passing", text)
    if m:  # mocha
        t["passed"] = int(m.group(1))
        f = re.search(r"(\d+) failing", text)
        t["failed"] = int(f.group(1)) if f else 0
        p = re.search(r"(\d+) pending", text)
        t["skipped"] = int(p.group(1)) if p else 0
        t["failing"] = sorted(set(re.findall(r"^\s+\d+\) (.+)$", text, re.M)))[:50]
        return t
    m = re.search(r"Tests:\s+(?:(\d+) failed, )?(?:(\d+) skipped, )?(\d+) passed", text)
    if m:  # jest / vitest
        t["failed"], t["skipped"], t["passed"] = int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3))
        t["failing"] = sorted(set(re.findall(r"●\s+(.+?)\s*$", text, re.M)))[:50]
    return t


# ---------------- applying changes ----------------
def apply_change(wt: Path, c: dict, git) -> str:
    f = wt / c["file"]
    if c["op"] in ("set-dependency", "add-override", "remove-dependency", "set-json"):
        data = json.loads(f.read_text(encoding="utf-8"))
        if c["op"] == "set-dependency":
            sec = c.get("section") or "dependencies"
            old = data.setdefault(sec, {}).get(c["target"])
            data[sec][c["target"]] = c["value"]
            msg = f"{c['file']}: {sec}.{c['target']} {old} → {c['value']}"
        elif c["op"] == "add-override":
            data.setdefault("overrides", {})[c["target"]] = c["value"]
            msg = f"{c['file']}: overrides.{c['target']} = {c['value']}"
        elif c["op"] == "remove-dependency":
            for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                data.get(sec, {}).pop(c["target"], None)
            msg = f"{c['file']}: removed {c['target']}"
        else:
            keys = c["target"].split(".")
            cur = data
            for k in keys[:-1]:
                cur = cur.setdefault(k, {})
            cur[keys[-1]] = json.loads(c["value"]) if c["value"] in ("true", "false", "null") or c["value"][:1] in "[{0123456789" else c["value"]
            msg = f"{c['file']}: {c['target']} = {c['value']}"
        indent = "\t" if "\n\t" in f.read_text(encoding="utf-8")[:200] else 2
        f.write_text(json.dumps(data, indent=indent, ensure_ascii=False) + "\n", encoding="utf-8")
        return msg
    if c["op"] == "replace-text":
        text = f.read_text(encoding="utf-8")
        if c["target"] not in text:
            raise RuntimeError(f"{c['target']} not found in {c['file']}")
        f.write_text(text.replace(c["target"], c["value"]), encoding="utf-8")
        return f"{c['file']}: {c['target']} → {c['value']}"
    if c["op"] == "restore-file":
        r = git(["checkout", c["value"], "--", c["file"]])
        if r["code"]:
            raise RuntimeError(r["stderr"][-300:])
        return f"{c['file']}: restored from {c['value']}"
    raise RuntimeError(f"unknown change op {c['op']}")


# ---------------- one sandbox run ----------------
def _err_line(text: str) -> str:
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    hit = next((l for l in lines if "Error" in l or "error" in l), None)
    return (hit or (lines[-1] if lines else ""))[:300]


def reviewer_email(repo: Path, name: str) -> str:
    """The approver's address for git: their own git user.email when the name matches, else a local placeholder."""
    cfg_name = run([tool("git"), "-C", str(repo), "config", "user.name"])["stdout"].strip()
    cfg_mail = run([tool("git"), "-C", str(repo), "config", "user.email"])["stdout"].strip()
    if cfg_mail and cfg_name and cfg_name.lower().split()[0] == name.lower().split()[0]:
        return cfg_mail
    return re.sub(r"[^a-z0-9.]+", ".", name.lower()).strip(".") + "@reviewer.local"


def commit_message(actions: list, decisions: dict, run_id: str, repo: Path) -> str:
    """Subject says who approved it (visible in `git log --oneline`); trailers record every approval."""
    names = []
    for a in actions:
        who = (decisions.get(a["id"]) or {}).get("reviewer", "unknown")
        if who not in names:
            names.append(who)
    subject = f"Guardian fix approved by {', '.join(names)}: {', '.join(a['id'] for a in actions)}"
    body = [f"- {a['id']} {a['title']}" for a in actions]
    trailers = []
    for a in actions:
        d = decisions.get(a["id"]) or {}
        who = d.get("reviewer", "unknown")
        trailers.append(f"Approved-by: {who} <{reviewer_email(repo, who)}> ({a['id']}, {d.get('at', '?')})")
        if d.get("comment"):
            trailers.append(f"Approval-comment: {a['id']}: {d['comment'][:150]}")
    trailers.append(f"Validated-by: Software Supply Chain Guardian, sandbox run {run_id}")
    return subject + "\n\n" + "\n".join(body) + "\n\n" + "\n".join(trailers) + "\n"


def run_case(repo: Path, base: str, name: str, actions: list, vdir: Path, run_id: str, prof: dict,
             scanner: str, log, run_tests: bool = True, keep: bool = False, smoke_pkgs: list = None,
             decisions: dict = None) -> dict:
    from guardian.workflow import run as day1_run
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    branch = f"guardian/{run_id}-{slug}"
    wt = SANDBOX / repo.name / f"{run_id}-{slug}"
    cdir = vdir / slug
    cdir.mkdir(parents=True, exist_ok=True)
    res = {"name": name, "actions": [a["id"] for a in actions], "branch": branch, "worktree": str(wt), "steps": [],
           "tests": None, "smoke": [], "scan": None, "applied": [], "commit": None, "snapshot": None}

    def step(label, status, seconds=0.0, detail="", out=None):
        logf = None
        if out is not None:
            logf = cdir / f"{len(res['steps']) + 1:02d}-{re.sub(r'[^a-z0-9]+', '-', label.lower())}.log"
            logf.write_text(f"$ {out['cmd']}\nexit {out['code']} in {out['seconds']}s\n\n{out['stdout']}\n{out['stderr']}", encoding="utf-8")
        res["steps"].append({"step": label, "status": status, "seconds": seconds, "detail": detail,
                             "log": logf.relative_to(vdir).as_posix() if logf else None})
        log(f"[{name}] {label}: {status}" + (f" - {detail}" if detail else ""))

    def git(args, cwd=wt):
        return run([tool("git"), "-c", "user.name=Guardian sandbox", "-c", "user.email=guardian@localhost",
                    "-c", "core.longpaths=true", "-c", "commit.gpgsign=false"] + args, cwd=cwd, timeout=300)

    if wt.exists():
        git(["worktree", "remove", "--force", str(wt)], cwd=repo)
        if wt.exists():
            remove_tree(wt)
    wt.parent.mkdir(parents=True, exist_ok=True)
    r = git(["worktree", "add", "-f", "-b", branch, str(wt), base], cwd=repo)
    if r["code"]:
        step("Create sandbox branch", "fail", r["seconds"], r["stderr"][-300:], r)
        return res
    # snapshot = the code exactly as it was scanned (package.json + lockfile from your working copy)
    for fname in ("package.json", "package-lock.json"):
        if (repo / fname).exists():
            shutil.copy2(repo / fname, wt / fname)
    git(["add", "-f", "package.json", "package-lock.json"])
    git(["commit", "--allow-empty", "-q", "-m", "Guardian sandbox: baseline snapshot"])
    res["snapshot"] = git(["rev-parse", "HEAD"])["stdout"].strip()
    step("Create sandbox branch", "pass", r["seconds"], f"{branch} at {res['snapshot'][:9]}")

    # apply
    if actions:
        try:
            for a in actions:
                for c in a["changes"]:
                    res["applied"].append(apply_change(wt, c, git))
        except Exception as err:
            step("Apply change", "fail", 0, str(err))
            return res
        step("Apply change", "pass", 0, "; ".join(res["applied"])[:400])
        if any(c["file"] == "package.json" for a in actions for c in a["changes"]):
            base_cmd = [tool("npm"), "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"]
            r = run(base_cmd, cwd=wt, timeout=900)
            if r["code"] and "ERESOLVE" in (r["stderr"] + r["stdout"]):
                r = run(base_cmd + ["--legacy-peer-deps"], cwd=wt, timeout=900)
            ok = r["code"] == 0
            step("Resolve dependency tree", "pass" if ok else "fail", r["seconds"],
                 "lockfile regenerated, no scripts run" if ok else (r["stderr"].strip().splitlines() or ["npm failed"])[-1][:300], r)
            if not ok:
                return res
        changed = sorted({c["file"] for a in actions for c in a["changes"]} | {"package-lock.json"})
        git(["add", "-f"] + [c for c in changed if (wt / c).exists()])
        msgfile = cdir / "commit-message.txt"
        msgfile.write_text(commit_message(actions, decisions or {}, run_id, repo), encoding="utf-8")
        git(["commit", "-q", "--author", "Software Supply Chain Guardian <guardian@localhost>", "-F", str(msgfile)])
        res["commit"] = git(["rev-parse", "HEAD"])["stdout"].strip()
        patch = git(["diff", res["snapshot"], res["commit"], "--", ".", ":(exclude)package-lock.json"])["stdout"]
        lockstat = git(["diff", "--shortstat", res["snapshot"], res["commit"], "--", "package-lock.json"])["stdout"].strip()
        (cdir / "remediation.patch").write_text(patch, encoding="utf-8")
        res["patch"] = (cdir / "remediation.patch").relative_to(vdir).as_posix()
        res["lockfile_diff"] = lockstat or "no lockfile change"

    # install / build / test
    r = run(prof["install"], cwd=wt, timeout=1200)
    step("Install (npm ci --ignore-scripts)", "pass" if r["code"] == 0 else "fail", r["seconds"],
         (re.search(r"added \d+ packages[^\n]*", r["stdout"] + r["stderr"]) or [""])[0] if r["code"] == 0 else r["stderr"].strip()[-300:], r)
    installed = r["code"] == 0
    if prof["build"] and installed:
        r = run(prof["build"], cwd=wt, timeout=1200)
        errs = len(re.findall(r"error TS\d+", r["stdout"] + r["stderr"]))
        step("Build", "pass" if r["code"] == 0 else "fail", r["seconds"],
             " ".join(prof["build"][1:]) + (f" - {errs} TypeScript errors" if errs else ""), r)
    else:
        step("Build", "skip", 0, "no build script found" if installed else "install failed")
    if prof["test"] and installed and run_tests:
        r = run(prof["test"], cwd=wt, timeout=1800, env_extra={"NODE_ENV": "test"})
        t = parse_tests(r["stdout"] + "\n" + r["stderr"])
        res["tests"] = t
        detail = (f"{t['passed']} passed, {t['failed']} failed" + (f", {t['skipped']} skipped" if t['skipped'] else "")) \
            if t["passed"] is not None else f"exit code {r['code']}"
        step("Unit tests", "pass" if r["code"] == 0 else "fail", r["seconds"], " ".join(prof["test"][1:]) + ": " + detail, r)
    else:
        step("Unit tests", "skip", 0, "no unit-test script found" if installed and run_tests else "skipped")
    # smoke: load every package the fix changed, once (the baseline loads the same names, for comparison)
    if installed:
        pkgs = smoke_pkgs if smoke_pkgs is not None else sorted({c["target"] for a in actions for c in a["changes"]
                                                                 if c["op"] in ("set-dependency", "add-override")})
        for pkg in pkgs:
            r = run([tool("node"), "--input-type=module", "-e", f"await import({json.dumps(pkg)})"], cwd=wt, timeout=120)
            res["smoke"].append({"package": pkg, "ok": r["code"] == 0, "error": _err_line(r["stderr"]) if r["code"] else ""})
        if res["smoke"]:
            bad = [s["package"] for s in res["smoke"] if not s["ok"]]
            good = [s["package"] for s in res["smoke"] if s["ok"]]
            detail = "; ".join(x for x in [", ".join(good) + " load" if good else "", "cannot load " + ", ".join(bad) if bad else ""] if x)
            # in the reference run this only records what loads before any change
            step("Load changed packages", ("info" if not actions else "fail") if bad else "pass", 0, detail)

    # rescan with the Day 1 agents (without node_modules, exactly like the original scan)
    if (wt / "node_modules").exists() and not keep:
        remove_tree(wt / "node_modules")
    os.environ["GUARDIAN_NO_PDF"] = "1"
    try:
        start = datetime.now()
        state = day1_run(str(wt), str(cdir / "scan"), base_ref=res["snapshot"], scanner=scanner)
        rep = read_json(cdir / "scan" / "evidence_report.json", {})
        vf = read_json(cdir / "scan" / "vulnerability_findings.json", {"findings": []})
        res["scan"] = {"dir": (cdir / "scan").relative_to(vdir).as_posix(), "scanner": rep.get("scanner"),
                       "advisories": len(vf["findings"]), "by_severity": vf.get("by_severity", {}),
                       "errors": state.get("errors", [])}
        step("Rescan (Day 1 agents)", "fail" if state.get("errors") else "pass", round((datetime.now() - start).total_seconds(), 1),
             f"{len(vf['findings'])} advisories via {rep.get('scanner')}")
    except Exception as err:
        step("Rescan (Day 1 agents)", "fail", 0, str(err)[:300])
    finally:
        os.environ.pop("GUARDIAN_NO_PDF", None)
    if not keep:
        git(["worktree", "remove", "--force", str(wt)], cwd=repo)
        if wt.exists():
            remove_tree(wt)
        res["worktree"] = None
        if not actions:  # the reference run changes nothing, so its branch is not kept
            git(["branch", "-D", branch], cwd=repo)
            res["branch"] = None
    return res


# ---------------- comparison ----------------
def _sbom_set(scan_dir: Path) -> set:
    rep = read_json(scan_dir / "evidence_report.json", {})
    path = (rep.get("sbom") or {}).get("path")
    if not path or not Path(path).exists():
        return set()
    bom = read_json(Path(path), {})
    out = set()
    for c in bom.get("components", []):
        if c.get("purl", "").startswith("pkg:npm/"):
            n = f"{c['group']}/{c['name']}" if c.get("group") else c["name"]
            out.add((n, c.get("version")))
    return out


def _inv_set(scan_dir: Path) -> dict:
    deps = (read_json(scan_dir / "dependency_inventory.json", {}) or {}).get("dependencies", [])
    return {(d["name"], d["version"]): d for d in deps}


def compare(before: dict, after: dict, vdir: Path, actions: list) -> dict:
    if not before.get("scan") or not after.get("scan"):
        return {}
    b, a = vdir / before["scan"]["dir"], vdir / after["scan"]["dir"]
    vb = read_json(b / "vulnerability_findings.json", {"findings": []})["findings"]
    va = read_json(a / "vulnerability_findings.json", {"findings": []})["findings"]
    kb = {(f["id"], f["package"], f["installed_version"]): f for f in vb}
    ka = {(f["id"], f["package"], f["installed_version"]): f for f in va}
    resolved = [kb[k] for k in kb if k not in ka]
    new = [ka[k] for k in ka if k not in kb]
    sb, sa = _sbom_set(b), _sbom_set(a)
    ib, ia = _inv_set(b), _inv_set(a)
    names_b = {n for n, _ in ib}
    added = sorted(f"{n}@{v}" for n, v in set(ia) - set(ib))
    removed = sorted(f"{n}@{v}" for n, v in set(ib) - set(ia))
    changed = sorted({n for n, _ in set(ia) ^ set(ib) if n in names_b and n in {x for x, _ in ia}})
    new_pkgs = sorted({n for n, _ in ia} - names_b)
    had_scripts = {n for (n, _), d in ib.items() if d.get("has_install_script")}
    new_scripts = sorted(f"{n}@{v}" for (n, v), d in ia.items() if d.get("has_install_script") and n not in had_scripts)
    targeted = {tuple(p.rsplit("@", 1)) for x in actions for p in x.get("covers_packages", [])}
    still = [f for f in va if (f["package"], f["installed_version"]) in targeted]
    sus_a = read_json(a / "suspicious_changes.json", {"findings": []})["findings"]

    def counts(fs):
        return {s: sum(1 for f in fs if f["severity"] == s) for s in SEV if any(f["severity"] == s for f in fs)}
    from guardian import analysis
    inv_b, inv_a = read_json(b / "inventory.json", {}), read_json(a / "inventory.json", {})
    gb = analysis.risk_grade(vb, [], inv_b)
    ga = analysis.risk_grade(va, [], inv_a)
    return {
        "advisories_before": len(vb), "advisories_after": len(va),
        "severity_before": counts(vb), "severity_after": counts(va),
        "grade_before": f"{gb[1]} ({gb[0]})", "grade_after": f"{ga[1]} ({ga[0]})",
        "resolved": [{"id": f["id"], "package": f"{f['package']}@{f['installed_version']}", "severity": f["severity"]} for f in resolved],
        "new_vulnerabilities": [{"id": f["id"], "package": f"{f['package']}@{f['installed_version']}", "severity": f["severity"],
                                 "title": f["title"]} for f in new],
        "targeted_still_vulnerable": sorted({f"{f['package']}@{f['installed_version']}" for f in still}),
        "sbom_components_before": len(sb), "sbom_components_after": len(sa),
        "sbom_added": sorted(f"{n}@{v}" for n, v in sa - sb)[:300], "sbom_removed": sorted(f"{n}@{v}" for n, v in sb - sa)[:300],
        "packages_before": len(ib), "packages_after": len(ia),
        "added": added[:300], "removed": removed[:300], "versions_changed": changed[:200],
        "new_dependencies": new_pkgs[:200], "new_install_scripts": new_scripts,
        "anomalies_from_change": [{"title": s["title"], "file": s["file"], "severity": s["severity"]}
                                  for s in sus_a if s["kind"] == "change"],
    }


def verdict(case: dict, base: dict, diff: dict, actions: list) -> tuple[str, list]:
    reasons, status = [], "Verified"
    steps = {s["step"]: s["status"] for s in case["steps"]}
    bsteps = {s["step"]: s["status"] for s in base["steps"]}
    for k in ("Create sandbox branch", "Apply change", "Resolve dependency tree", "Install (npm ci --ignore-scripts)"):
        if steps.get(k) == "fail":
            return "Failed validation", [f"{k} failed"]
    if steps.get("Build") == "fail" and bsteps.get("Build") != "fail":
        detail = next((x["detail"] for x in case["steps"] if x["step"] == "Build"), "")
        tests = case.get("tests") or {}
        extra = f"; {tests['failed']} unit tests also fail" if tests.get("failed") else ""
        return "Failed validation", [f"the build breaks with this change but not without it ({detail}){extra}"]
    tb, ta = base.get("tests") or {}, case.get("tests") or {}
    new_fail = sorted(set(ta.get("failing") or []) - set(tb.get("failing") or []))
    if steps.get("Unit tests") == "fail" and bsteps.get("Unit tests") != "fail":
        return "Failed validation", [f"unit tests fail with this change: {ta.get('failed')} failing"
                                     + (f" ({', '.join(new_fail[:3])})" if new_fail else "")]
    if (ta.get("failed") or 0) > (tb.get("failed") or 0):
        return "Failed validation", [f"{ta['failed'] - (tb.get('failed') or 0)} more failing tests than the baseline"]
    base_ok = {s["package"]: s["ok"] for s in base.get("smoke", [])}
    broken = [s for s in case.get("smoke", []) if not s["ok"] and base_ok.get(s["package"], True)]
    if broken:
        return "Failed validation", [f"{broken[0]['package']} cannot be loaded after the change: {broken[0]['error']}"]
    for s in case.get("smoke", []):
        if not s["ok"]:
            status = "Verified with notes"
            reasons.append(f"{s['package']} cannot be loaded in the sandbox before or after the change (a native module is not "
                           "built while install scripts are disabled), so the load check is inconclusive for it")
    if not diff:
        return "Not verified", ["the rescan did not complete"]
    crit_new = [v for v in diff["new_vulnerabilities"] if v["severity"] in ("critical", "high")]
    if crit_new:
        return "Failed validation", [f"introduces {len(crit_new)} new critical/high advisories: " + ", ".join(v["id"] for v in crit_new[:4])]
    if diff["targeted_still_vulnerable"]:
        status = "Verified with notes"
        reasons.append("still vulnerable after the change: " + ", ".join(diff["targeted_still_vulnerable"][:5]))
    if diff["new_vulnerabilities"]:
        status = "Verified with notes"
        reasons.append(f"{len(diff['new_vulnerabilities'])} new lower-severity advisories")
    if diff["new_install_scripts"]:
        status = "Verified with notes"
        reasons.append("new packages with install scripts: " + ", ".join(diff["new_install_scripts"][:4]))
    if steps.get("Build") == "skip" or steps.get("Unit tests") == "skip":
        reasons.append("no build or unit tests available, so behaviour was not tested")
        if status == "Verified":
            status = "Verified with notes"
    n = len(diff["resolved"])
    built = "builds" if steps.get("Build") == "pass" else "no build step"
    tested = f"{ta.get('passed')} tests pass" if ta.get("passed") is not None else "tests not run"
    summary = (f"{built}, {tested}, {n} advisor{'y' if n == 1 else 'ies'} resolved"
               + (", nothing new introduced" if not diff["new_vulnerabilities"] and not diff["new_install_scripts"] else ""))
    return status, [summary] + reasons


def tag_release(repo: Path, rc: dict, actions: list, decisions: dict, run_id: str):
    """An annotated tag on the validated commit, created in the approver's name: `git tag -n` shows who approved it."""
    who = {}
    for a in actions:
        r = (decisions.get(a["id"]) or {}).get("reviewer", "unknown")
        who.setdefault(r, []).append(a["id"])
    lead = max(who, key=lambda k: len(who[k]))
    d = rc.get("diff") or {}
    t = rc.get("tests") or {}
    approvers = ", ".join(f"{k} ({len(v)} fix{'es' if len(v) != 1 else ''})" for k, v in who.items())
    msg = (f"Approved by {approvers}; "
           f"validated by the Guardian: {rc['verdict']}\n\n"
           + "\n".join(f"{a['id']} {a['title']} - approved by {(decisions.get(a['id']) or {}).get('reviewer', '?')} "
                       f"on {(decisions.get(a['id']) or {}).get('at', '?')}" for a in actions)
           + f"\n\nAdvisories {d.get('advisories_before')} -> {d.get('advisories_after')}; unit tests {t.get('passed')} passed, "
             f"{t.get('failed')} failed; {len(d.get('new_vulnerabilities', []))} new advisories.\n")
    name = f"guardian-approved/{run_id}"
    r = run([tool("git"), "-C", str(repo), "-c", f"user.name={lead}", "-c", f"user.email={reviewer_email(repo, lead)}",
             "tag", "-a", "-f", name, rc["commit"], "-m", msg], timeout=60)
    return name if r["code"] == 0 else None


def validate(repo: Path, out: Path, actions: list, mode: str = "each", run_tests: bool = True,
             keep: bool = False, log=print) -> dict:
    repo, out = Path(repo).resolve(), Path(out)
    if not actions:
        raise RuntimeError("No approved actions to validate. A person must approve at least one action first.")
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    vdir = day2_dir(out) / "validation" / run_id
    vdir.mkdir(parents=True, exist_ok=True)
    base = run([tool("git"), "-C", str(repo), "rev-parse", "HEAD"])["stdout"].strip()
    scanner = (read_json(out / "vulnerability_findings.json", {}) or {}).get("scanner") or "auto"
    prof = profile(repo)
    audit(out, "agent:validation", "validation-started", {"run": run_id, "actions": [a["id"] for a in actions],
                                                          "base_commit": base, "profile": {k: " ".join(map(str, v)) if v else None for k, v in prof.items()}})
    log(f"Sandbox: {SANDBOX / repo.name}  |  base commit {base[:9]}  |  scanner {scanner}")
    from guardian.day2 import approvals
    decisions = approvals.current(out)
    smoke = sorted({c["target"] for a in actions for c in a["changes"] if c["op"] in ("set-dependency", "add-override")})
    baseline = run_case(repo, base, "baseline", [], vdir, run_id, prof, scanner, log, run_tests, keep, smoke_pkgs=smoke)
    cases = []
    if mode == "each" and len(actions) > 1:
        for a in actions:
            c = run_case(repo, base, a["id"], [a], vdir, run_id, prof, scanner, log, run_tests, keep, decisions=decisions)
            c["diff"] = compare(baseline, c, vdir, [a])
            c["verdict"], c["reasons"] = verdict(c, baseline, c["diff"], [a])
            if c["verdict"] == "Failed validation" and c.get("branch"):
                # make a failed fix impossible to mistake for a good one in `git branch`
                r = run([tool("git"), "-C", str(repo), "branch", "-m", c["branch"], c["branch"] + "-failed"])
                if r["code"] == 0:
                    c["branch"] += "-failed"
            audit(out, "agent:validation", "action-validated", {"run": run_id, "action": a["id"], "verdict": c["verdict"],
                                                                "reasons": c["reasons"], "commit": c.get("commit")})
            cases.append(c)
        passing = [a for a, c in zip(actions, cases) if c["verdict"].startswith("Verified")]
    else:
        passing = actions
    combined = None
    if passing:
        combined = run_case(repo, base, "release candidate", passing, vdir, run_id, prof, scanner, log, run_tests, keep,
                            decisions=decisions)
        combined["diff"] = compare(baseline, combined, vdir, passing)
        combined["verdict"], combined["reasons"] = verdict(combined, baseline, combined["diff"], passing)
        if mode != "each" or len(actions) == 1:
            for a in actions:
                audit(out, "agent:validation", "action-validated", {"run": run_id, "action": a["id"], "verdict": combined["verdict"],
                                                                    "reasons": combined["reasons"], "commit": combined.get("commit")})
        if combined.get("commit") and combined["verdict"].startswith("Verified"):
            combined["tag"] = tag_release(repo, combined, passing, decisions, run_id)
        audit(out, "agent:validation", "release-candidate", {"run": run_id, "actions": [a["id"] for a in passing],
                                                             "verdict": combined["verdict"], "branch": combined["branch"],
                                                             "commit": combined.get("commit")})
    result = {"run": run_id, "base_commit": base, "repo": str(repo), "scanner": scanner, "mode": mode,
              "profile": {k: " ".join(map(str, v)) if v else None for k, v in prof.items()},
              "baseline": baseline, "cases": cases, "combined": combined,
              "approved": [a["id"] for a in actions], "passed": [a["id"] for a in passing]}
    write_json(vdir / "validation.json", result)
    write_json(day2_dir(out) / "validation_latest.json", {**result, "dir": vdir.relative_to(out).as_posix()})
    return result
