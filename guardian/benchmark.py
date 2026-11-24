"""Benchmark: the Guardian against other open-source tools built for the same job, on the same repositories.

Tools: npm audit (GitHub Advisory DB), OSV-Scanner (osv.dev), Grype (Anchore DB), Trivy (Aqua DB), and the
Guardian itself. Each tool that is installed is run on the same lockfile. Findings are normalised to
(package, installed version, vulnerability) where CVE and GHSA ids for the same bug are merged using the
aliases the tools themselves report (plus osv.dev lookups when online).

There is no perfect ground truth for "which advisories really apply", so the reference set is the
consensus of independent databases: a finding counts as confirmed when at least two of npm audit, OSV,
Grype and Trivy report it. The Guardian is not a voter because it reuses OSV/npm audit. Precision, recall
and F1 are measured against that reference, overall and for production packages only.

A second, separate test measures non-CVE supply-chain detection on planted anomalies in a throwaway local
git repository (nothing is installed or published). It is clearly labelled as a controlled test.

    python -m guardian.benchmark                       # every repository in target/
    python -m guardian.benchmark --repos juice-shop NodeGoat
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

from guardian.agents.sbom import find_tool
from guardian.agents.vulnerability import parse_npm_audit, parse_osv
from guardian.repo_fetch import ROOT, TARGETS, out_dir_for

BENCH = ROOT / "reports" / "benchmark"
VOTERS = ["npm-audit", "osv-scanner", "grype", "trivy"]
TOOLS = ["guardian"] + VOTERS
SEV_NORM = {"moderate": "medium", "negligible": "low", "unknown": "unknown", "info": "low"}


def norm_sev(s):
    s = (s or "unknown").lower()
    return SEV_NORM.get(s, s)


def sh(cmd, cwd=None, timeout=900):
    t = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr, round(time.time() - t, 1)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e), round(time.time() - t, 1)


def workspace(repo: Path) -> Path:
    """Only package.json + package-lock.json, so every tool sees exactly the same input."""
    ws = Path(tempfile.mkdtemp(prefix="guardian-bench-"))
    for f in ("package.json", "package-lock.json"):
        shutil.copy2(repo / f, ws / f)
    return ws


# ---------------- adapters: each returns {"status", "seconds", "raw_rows", "findings", "note", "version"} ----------------
def run_guardian(repo: Path, ws: Path, out: Path) -> dict:
    from guardian.workflow import run as day1
    os.environ["GUARDIAN_NO_PDF"] = "1"
    t = time.time()
    try:
        day1(str(repo), str(out / "guardian"), scanner="auto")
    finally:
        os.environ.pop("GUARDIAN_NO_PDF", None)
    secs = round(time.time() - t, 1)
    vf = json.loads((out / "guardian" / "vulnerability_findings.json").read_text(encoding="utf-8"))
    rows = [{"package": f["package"], "version": f["installed_version"], "ids": [f["id"]] + f.get("aliases", []),
             "severity": f["severity"], "fixed": bool(f.get("fixed_version")), "path": bool(f.get("dependency_path"))}
            for f in vf["findings"]]
    return {"status": "ok", "seconds": secs, "raw_rows": len(vf["findings"]), "findings": rows,
            "note": f"full 5-agent pipeline (SBOM, graph, {vf['scanner']}, anomalies) - time includes all of it",
            "version": "this project"}


def run_npm_audit(repo: Path, ws: Path, out: Path) -> dict:
    code, so, se, secs = sh([find_tool("npm") or "npm", "audit", "--json", "--package-lock-only"], cwd=ws)
    try:
        data = json.loads(so)
    except json.JSONDecodeError:
        return {"status": "error", "seconds": secs, "note": se[-300:]}
    if "error" in data:
        return {"status": "error", "seconds": secs, "note": str(data["error"])[:300]}
    (out / "npm-audit.json").write_text(so, encoding="utf-8")
    lock = json.loads((ws / "package-lock.json").read_text(encoding="utf-8"))["packages"]
    rows = [{"package": r["package"], "version": r["installed_version"], "ids": [r["id"]], "severity": r["severity"],
             "fixed": bool(r.get("fixed_version")), "path": bool(r.get("lock_path"))} for r in parse_npm_audit(data, lock)]
    raw = sum(1 for e in data.get("vulnerabilities", {}).values() for v in e.get("via", []) if isinstance(v, dict))
    _, ver, _, _ = sh([find_tool("npm") or "npm", "--version"])
    return {"status": "ok", "seconds": secs, "raw_rows": raw, "findings": rows, "version": f"npm {ver.strip()}",
            "note": "reports per package name; versions mapped from the lockfile"}


def run_osv(repo: Path, ws: Path, out: Path) -> dict:
    osv = find_tool("osv-scanner")
    if not osv:
        return {"status": "unavailable", "note": "osv-scanner not installed (setup.bat puts it in tools/)"}
    code, so, se, secs = sh([osv, "scan", "source", "--lockfile", str(ws / "package-lock.json"), "--format", "json"])
    if code not in (0, 1) or not so.strip():
        return {"status": "error", "seconds": secs, "note": (se or so)[-300:]}
    (out / "osv-scanner.json").write_text(so, encoding="utf-8")
    data = json.loads(so)
    rows = [{"package": r["package"], "version": r["installed_version"], "ids": [r["id"]] + r.get("aliases", []),
             "severity": r["severity"], "fixed": bool(r.get("fixed_version")), "path": False} for r in parse_osv(data)]
    raw = sum(len(p.get("vulnerabilities", [])) for res in data.get("results", []) for p in res.get("packages", []))
    _, ver, _, _ = sh([osv, "--version"])
    return {"status": "ok", "seconds": secs, "raw_rows": raw, "findings": rows, "version": ver.strip().splitlines()[0] if ver else ""}


def parse_grype(data: dict) -> list:
    rows = []
    for m in data.get("matches", []):
        a, v = m.get("artifact", {}), m.get("vulnerability", {})
        if a.get("type") not in (None, "npm"):
            continue
        ids = [v.get("id")] + [r.get("id") for r in m.get("relatedVulnerabilities", []) if r.get("id")]
        rows.append({"package": a.get("name"), "version": a.get("version"), "ids": [i for i in ids if i],
                     "severity": norm_sev(v.get("severity")), "fixed": bool((v.get("fix") or {}).get("versions")), "path": False})
    return rows


def run_grype(repo: Path, ws: Path, out: Path) -> dict:
    g = find_tool("grype")
    if not g:
        return {"status": "unavailable", "note": "grype not installed (run benchmark_tools.bat)"}
    code, so, se, secs = sh([g, f"dir:{ws}", "-o", "json", "-q"], timeout=1200)
    if code != 0 or not so.strip():
        return {"status": "error", "seconds": secs, "note": (se or so)[-300:]}
    (out / "grype.json").write_text(so, encoding="utf-8")
    data = json.loads(so)
    _, ver, _, _ = sh([g, "version"])
    return {"status": "ok", "seconds": secs, "raw_rows": len(data.get("matches", [])), "findings": parse_grype(data),
            "version": next((l.split(":", 1)[1].strip() for l in ver.splitlines() if l.lower().startswith("version")), ""),
            "note": "first run also downloads Grype's database"}


def parse_trivy(data: dict) -> list:
    rows = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            ids = [v.get("VulnerabilityID")] + list(v.get("VendorIDs") or [])
            rows.append({"package": v.get("PkgName"), "version": v.get("InstalledVersion"), "ids": [i for i in ids if i],
                         "severity": norm_sev(v.get("Severity")), "fixed": bool(v.get("FixedVersion")), "path": False})
    return rows


def run_trivy(repo: Path, ws: Path, out: Path) -> dict:
    tv = find_tool("trivy")
    if not tv:
        return {"status": "unavailable", "note": "trivy not installed (run benchmark_tools.bat)"}
    code, so, se, secs = sh([tv, "fs", "--scanners", "vuln", "--include-dev-deps", "--format", "json", "--quiet", str(ws)], timeout=1200)
    if code != 0 or not so.strip():
        return {"status": "error", "seconds": secs, "note": (se or so)[-300:]}
    (out / "trivy.json").write_text(so, encoding="utf-8")
    data = json.loads(so)
    _, ver, _, _ = sh([tv, "--version"])
    return {"status": "ok", "seconds": secs, "raw_rows": sum(len(r.get("Vulnerabilities") or []) for r in data.get("Results") or []),
            "findings": parse_trivy(data), "version": (ver.splitlines() or [""])[0].replace("Version:", "").strip(),
            "note": "run with --include-dev-deps so dev packages are compared too; first run downloads Trivy's database"}


ADAPTERS = {"guardian": run_guardian, "npm-audit": run_npm_audit, "osv-scanner": run_osv, "grype": run_grype, "trivy": run_trivy}


# ---------------- normalisation ----------------
class Aliases:
    def __init__(self, cache_file: Path):
        self.parent = {}
        self.cache_file = cache_file
        self.cache = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, ids):
        ids = [i for i in ids if i]
        for i in ids[1:]:
            a, b = self.find(ids[0]), self.find(i)
            if a != b:
                self.parent[max(a, b)] = min(a, b)
        if ids:
            self.find(ids[0])

    def enrich(self, ids: set, online: bool):
        """Ask osv.dev for the aliases of ids no tool linked (GHSA-only or CVE-only)."""
        for i in sorted(ids):
            if i not in self.cache and online:
                try:
                    with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{i}", timeout=8) as r:
                        d = json.loads(r.read().decode("utf-8"))
                    self.cache[i] = d.get("aliases", []) + d.get("upstream", [])
                except Exception:
                    online = False  # stop trying once the API is unreachable
            if self.cache.get(i):
                self.union([i] + self.cache[i])
        self.cache_file.write_text(json.dumps(self.cache, indent=1), encoding="utf-8")


def f1(p, r):
    return round(2 * p * r / (p + r), 3) if p + r else 0.0


def score_repo(repo: Path, results: dict, aliases: Aliases, scope: dict) -> dict:
    for r in results.values():
        for f in r.get("findings", []):
            aliases.union(f["ids"])
    keyed = {}
    for tool, r in results.items():
        ks = {}
        for f in r.get("findings", []):
            k = (f["package"], f["version"], aliases.find(f["ids"][0]))
            ks.setdefault(k, f)
        keyed[tool] = ks
    ran = [t for t in VOTERS if results.get(t, {}).get("status") == "ok"]
    votes = Counter(k for t in ran for k in keyed[t])
    need = 2 if len(ran) >= 2 else 1
    reference = {k for k, n in votes.items() if n >= need}
    ref_prod = {k for k in reference if scope.get((k[0], k[1])) == "prod"}
    metrics = {}
    for tool, r in results.items():
        if r.get("status") != "ok":
            metrics[tool] = {"status": r.get("status"), "note": r.get("note", "")}
            continue
        ks = set(keyed[tool])
        tp, fp, fn = len(ks & reference), len(ks - reference), len(reference - ks)
        p = round(tp / (tp + fp), 3) if tp + fp else 0.0
        rc = round(tp / (tp + fn), 3) if tp + fn else 0.0
        kp = {k for k in ks if scope.get((k[0], k[1])) == "prod"}
        tpp, fpp, fnp = len(kp & ref_prod), len(kp - ref_prod), len(ref_prod - kp)
        pp = round(tpp / (tpp + fpp), 3) if tpp + fpp else 0.0
        rp = round(tpp / (tpp + fnp), 3) if tpp + fnp else 0.0
        sev_agree = []
        for k in ks & reference:
            maj = Counter(norm_sev(keyed[t][k]["severity"]) for t in ran if k in keyed[t]).most_common(1)[0][0]
            sev_agree.append(norm_sev(keyed[tool][k]["severity"]) == maj)
        found = list(keyed[tool].values())
        metrics[tool] = {
            "status": "ok", "version": r.get("version", ""), "seconds": r.get("seconds"), "raw_rows": r.get("raw_rows"),
            "unique_findings": len(ks), "duplicates_merged": max(0, (r.get("raw_rows") or 0) - len(ks)),
            "packages_flagged": len({(k[0], k[1]) for k in ks}),
            "tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": rc, "f1": f1(p, rc),
            "precision_prod": pp, "recall_prod": rp, "f1_prod": f1(pp, rp),
            "severity_agreement": round(sum(sev_agree) / len(sev_agree), 3) if sev_agree else None,
            "with_fix": round(sum(f["fixed"] for f in found) / len(found), 3) if found else None,
            "with_path": round(sum(f["path"] for f in found) / len(found), 3) if found else None,
            "unconfirmed_examples": sorted(f"{k[0]}@{k[1]} {k[2]}" for k in ks - reference)[:15],
            "missed_examples": sorted(f"{k[0]}@{k[1]} {k[2]}" for k in reference - ks)[:15], "note": r.get("note", ""),
        }
    overlap = {}
    for a in [t for t in TOOLS if metrics.get(t, {}).get("status") == "ok"]:
        for b in [t for t in TOOLS if metrics.get(t, {}).get("status") == "ok"]:
            A, B = set(keyed[a]), set(keyed[b])
            overlap[f"{a}|{b}"] = round(len(A & B) / len(A | B), 3) if A | B else 1.0
    return {"repo": repo.name, "voters": ran, "reference_rule": f"reported by at least {need} of {len(ran)} independent scanners",
            "reference_size": len(reference), "reference_prod": len(ref_prod),
            "single_source": len(ran) < 2, "metrics": metrics, "overlap": overlap}


# ---------------- controlled non-CVE test ----------------
CASES = [
    ("typosquat", "Typosquatted dependency added (expresss)", True),
    ("install-script", "New dependency with a postinstall script", True),
    ("lockfile-host", "Lockfile entry now downloads from a different host", True),
    ("lockfile-integrity", "Lockfile integrity hash changed", True),
    ("docker-latest", "Dockerfile base image changed to a mutable :latest tag", True),
    ("ci-unpinned", "CI action changed from a commit SHA to a branch", True),
    ("downgrade", "Dependency silently downgraded", True),
    ("unexpected-dep", "Unexpected new dependency added", True),
    ("control-patch", "Control: normal patch upgrade, nothing malicious", False),
    ("control-docs", "Control: README edit only", False),
]


def _git(args, cwd):
    return subprocess.run(["git", "-c", "user.name=bench", "-c", "user.email=bench@localhost", "-c", "commit.gpgsign=false"] + args,
                          cwd=cwd, capture_output=True, text=True)


def _base_project(d: Path):
    pkg = {"name": "bench-app", "version": "1.0.0", "dependencies": {"express": "4.21.2", "lodash": "4.17.21"}}
    lock = {"name": "bench-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": {"name": "bench-app", "version": "1.0.0", "dependencies": pkg["dependencies"]},
        "node_modules/express": {"version": "4.21.2", "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz",
                                 "integrity": "sha512-28HqgMZAmih1Czt9ny7qr6ek2qddF4FclbMzwhCREB6OFfH+rXAnuNCwo1/wFvrtbgsQDb4kSbX9de9lFbrXnA=="},
        "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                                "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="}}}
    (d / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    (d / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
    (d / "Dockerfile").write_text("FROM node:22.11.0-alpine@sha256:b64ced2e7cd0a4816699fe308ce6e8a08ccba463c757c00c14cd372e3d2c763e\nCOPY . /app\n", encoding="utf-8")
    (d / ".github" / "workflows").mkdir(parents=True)
    (d / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm ci --ignore-scripts\n", encoding="utf-8")
    (d / "README.md").write_text("# bench app\n", encoding="utf-8")


def _plant(case: str, d: Path):
    pkg = json.loads((d / "package.json").read_text())
    lock = json.loads((d / "package-lock.json").read_text())
    P = lock["packages"]
    if case in ("typosquat", "unexpected-dep", "install-script"):
        name = {"typosquat": "expresss", "unexpected-dep": "left-pad-utils-x", "install-script": "postinstall-helper-x"}[case]
        pkg["dependencies"][name] = "1.0.0"
        P[""]["dependencies"][name] = "1.0.0"
        P[f"node_modules/{name}"] = {"version": "1.0.0", "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
                                     "integrity": "sha512-" + "A" * 86 + "=="}
        if case == "install-script":
            P[f"node_modules/{name}"]["hasInstallScript"] = True
            pkg.setdefault("scripts", {})["postinstall"] = "node ./node_modules/postinstall-helper-x/setup.js"
    elif case == "lockfile-host":
        P["node_modules/lodash"]["resolved"] = "https://npm-mirror.example.net/lodash/-/lodash-4.17.21.tgz"
    elif case == "lockfile-integrity":
        P["node_modules/lodash"]["integrity"] = "sha512-" + "B" * 86 + "=="
    elif case == "downgrade":
        pkg["dependencies"]["lodash"] = "4.17.4"
        P[""]["dependencies"]["lodash"] = "4.17.4"
        P["node_modules/lodash"].update(version="4.17.4", resolved="https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
                                        integrity="sha512-6X37Sq9KCpLSXEh8uM12AKYlviHPNNk4RxiGBn4cmKGJinbXBneWIV7iE/nXkM928O7ytHcHb6+X6Svl0f4hXg==")
    elif case == "control-patch":
        pkg["dependencies"]["express"] = "4.21.3"
        P[""]["dependencies"]["express"] = "4.21.3"
        P["node_modules/express"].update(version="4.21.3", resolved="https://registry.npmjs.org/express/-/express-4.21.3.tgz")
    elif case == "docker-latest":
        (d / "Dockerfile").write_text("FROM node:latest\nCOPY . /app\n", encoding="utf-8")
    elif case == "ci-unpinned":
        wf = d / ".github" / "workflows" / "ci.yml"
        wf.write_text(wf.read_text().replace("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "someone/checkout-fork@main"))
    elif case == "control-docs":
        (d / "README.md").write_text("# bench app\n\nNow with docs.\n", encoding="utf-8")
    (d / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    (d / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")


def controlled_test(log=print) -> dict:
    from guardian.agents import discovery, suspicious
    rows = []
    root = Path(tempfile.mkdtemp(prefix="guardian-planted-"))
    for case, label, malicious in CASES:
        d = root / case
        d.mkdir()
        _base_project(d)
        _git(["init", "-q"], d)
        _git(["add", "-A"], d)
        _git(["commit", "-q", "-m", "baseline"], d)
        _plant(case, d)
        out = d / "_out"
        out.mkdir()
        res = {"case": case, "label": label, "planted": malicious, "detected": {}}
        inv = discovery.discover(d, out)
        found, _ = suspicious.detect(d, out, inv, "HEAD")
        hits = [f for f in found if f.kind == "change"]
        res["detected"]["guardian"] = bool(hits)
        res["guardian_findings"] = [f"{f.severity}: {f.title}" for f in hits][:4]
        # the vulnerability scanners, on the same planted copy
        ws = workspace(d)
        for tool in VOTERS:
            r = ADAPTERS[tool](d, ws, out) if tool != "grype" or find_tool("grype") else {"status": "unavailable"}
            if r.get("status") != "ok":
                res["detected"][tool] = None
                continue
            names = {f["package"] for f in r.get("findings", [])}
            res["detected"][tool] = bool(names & {"expresss", "left-pad-utils-x", "postinstall-helper-x"}) or \
                (case == "downgrade" and "lodash" in names)
        tv = find_tool("trivy")
        if tv and case in ("docker-latest", "control-docs", "control-patch"):
            code, so, _, _ = sh([tv, "config", "--format", "json", "--quiet", str(d)])
            try:
                mis = [m for r_ in json.loads(so).get("Results", []) or [] for m in r_.get("Misconfigurations", []) or []]
                res["detected"]["trivy"] = any("latest" in (m.get("Title", "") + m.get("Message", "")).lower() for m in mis)
            except json.JSONDecodeError:
                pass
        shutil.rmtree(ws, ignore_errors=True)
        rows.append(res)
        log(f"  planted {case}: " + ", ".join(f"{t}={'yes' if v else 'no' if v is False else 'n/a'}" for t, v in res["detected"].items()))
    shutil.rmtree(root, ignore_errors=True)
    summary = {}
    for tool in TOOLS:
        vals = [r for r in rows if r["detected"].get(tool) is not None]
        if not vals:
            summary[tool] = None
            continue
        planted = [r for r in vals if r["planted"]]
        controls = [r for r in vals if not r["planted"]]
        summary[tool] = {"detected": sum(r["detected"][tool] for r in planted), "planted": len(planted),
                         "recall": round(sum(r["detected"][tool] for r in planted) / len(planted), 3) if planted else None,
                         "false_alarms": sum(r["detected"][tool] for r in controls), "controls": len(controls)}
    return {"cases": rows, "summary": summary,
            "note": "Planted in a throwaway local git repository with a hand-written lockfile. Nothing is installed or published."}


def run(repos: list[Path], log=print, online: bool = True, controlled: bool = True) -> dict:
    BENCH.mkdir(parents=True, exist_ok=True)
    aliases = Aliases(BENCH / "osv_alias_cache.json")
    all_results = {}
    for repo in repos:
        log(f"== {repo.name}")
        out = BENCH / repo.name
        out.mkdir(parents=True, exist_ok=True)
        ws = workspace(repo)
        res = {}
        for tool in TOOLS:
            try:
                res[tool] = ADAPTERS[tool](repo, ws, out)
            except Exception as err:
                res[tool] = {"status": "error", "note": f"{type(err).__name__}: {err}"[:300]}
            r = res[tool]
            log(f"   {tool:12} {r['status']:12} " + (f"{len(r.get('findings', []))} findings in {r.get('seconds')}s" if r["status"] == "ok" else r.get("note", "")))
        shutil.rmtree(ws, ignore_errors=True)
        for r in res.values():
            for f in r.get("findings", []):
                aliases.union(f["ids"])
        lonely = {f["ids"][0] for r in res.values() for f in r.get("findings", []) if len(f["ids"]) == 1}
        aliases.enrich(lonely, online)
        deps = (json.loads((out_dir_for(repo) / "dependency_inventory.json").read_text(encoding="utf-8")) if (out_dir_for(repo) / "dependency_inventory.json").exists()
                else json.loads((out / "guardian" / "dependency_inventory.json").read_text(encoding="utf-8")))["dependencies"]
        scope = {(d["name"], d["version"]): ("prod" if d.get("scope") != "dev" else "dev") for d in deps}
        all_results[repo.name] = score_repo(repo, res, aliases, scope)
        (out / "tool_results.json").write_text(json.dumps({t: {k: v for k, v in r.items() if k != "findings"} for t, r in res.items()},
                                                          indent=2), encoding="utf-8")
    data = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "repos": all_results,
            "tools_available": {t: t in ("guardian", "npm-audit") or bool(find_tool(t)) for t in TOOLS}}
    if controlled:
        log("== controlled non-CVE test")
        data["controlled"] = controlled_test(log)
    data["analysis"] = analyse(data)
    (BENCH / "benchmark.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def analyse(data: dict) -> list[str]:
    """Plain sentences derived from the numbers (no LLM)."""
    lines = []
    for name, r in data["repos"].items():
        ok = {t: m for t, m in r["metrics"].items() if m.get("status") == "ok"}
        if r["single_source"]:
            lines.append(f"{name}: only {len(r['voters'])} independent scanner ran, so the reference is a single source and "
                         "precision/recall are not meaningful. Install OSV-Scanner, Grype or Trivy and run again.")
            continue
        best = max(ok, key=lambda t: ok[t]["f1"])
        lines.append(f"{name}: {r['reference_size']} findings confirmed by at least two databases. Best F1: {best} "
                     f"({ok[best]['f1']:.2f}; precision {ok[best]['precision']:.2f}, recall {ok[best]['recall']:.2f}).")
        for t, m in ok.items():
            if m["fp"] and t != "guardian":
                lines.append(f"{name}: {t} reports {m['fp']} findings no other database confirms (e.g. {', '.join(m['unconfirmed_examples'][:2])}).")
        g = ok.get("guardian")
        if g:
            lines.append(f"{name}: the Guardian merges {g['duplicates_merged']} duplicate rows, gives a fixed version for "
                         f"{(g['with_fix'] or 0) * 100:.0f}% and a dependency path for {(g['with_path'] or 0) * 100:.0f}% of findings; "
                         f"recall on production packages {g['recall_prod']:.2f}.")
    c = data.get("controlled")
    if c:
        for t, s in c["summary"].items():
            if s:
                lines.append(f"Controlled non-CVE test: {t} caught {s['detected']} of {s['planted']} planted anomalies with "
                             f"{s['false_alarms']} false alarms on {s['controls']} harmless changes.")
    return lines


def main():
    ap = argparse.ArgumentParser(description="Compare the Guardian with npm audit, OSV-Scanner, Grype and Trivy")
    ap.add_argument("--repos", nargs="*", help="names of folders in target/ (default: all)")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--skip-controlled", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    names = a.repos or [p.name for p in sorted(TARGETS.iterdir()) if (p / "package-lock.json").exists()]
    repos = [TARGETS / n for n in names if (TARGETS / n / "package-lock.json").exists()]
    if not repos:
        sys.exit("No repositories with a package-lock.json in target/. Run setup.bat or fetch one in the dashboard.")
    data = run(repos, online=not a.offline, controlled=not a.skip_controlled)
    print("\n" + "\n".join(data["analysis"]))
    print(f"\nSaved to {BENCH / 'benchmark.json'}. Open the dashboard: Evaluate > Benchmark.")


if __name__ == "__main__":
    main()
