"""Agent 6 - Risk Analysis, part 2: suspicious change investigation (risks that have no CVE).

Looks at install scripts, provenance (where packages come from, build attestations), integrity hashes,
deprecated packages, loose version ranges, manifest/lockfile consistency, container images and CI actions,
plus the Day 1 changes since the baseline.

Every item keeps two things apart:
  verified_evidence - facts read from the lockfile, package.json, git or the npm registry, each with its source
  inference         - an interpretation (LLM, grounding-checked, or rule-based), clearly labelled as such
Package scripts are downloaded as text from the registry and never executed.
"""
import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from guardian.day2.common import day2_dir, write_json
from guardian.models import Investigation

REGISTRY = "https://registry.npmjs.org"
SCRIPT_KEYS = ("preinstall", "install", "postinstall", "prepare")
NATIVE = re.compile(r"node-gyp|prebuild-install|node-pre-gyp|cmake-js|napi|neon", re.I)
DOWNLOAD = re.compile(r"curl|wget|https?://|download|install\.js|--exec install|fetch\(", re.I)
TELEMETRY = re.compile(r"report\.js|scarf|analytics|telemetry|track", re.I)
RISKY = re.compile(r"\beval\b|base64|child_process|\.ssh|\.npmrc|process\.env|/etc/passwd|powershell|\bsh -c\b|\|\s*sh", re.I)


def _get(url: str, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "software-supply-chain-guardian/2.0",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def registry_meta(pkgs: list[tuple[str, str]], raw_dir: Path) -> dict:
    """Version manifests from the public npm registry (read-only). Cached in raw/registry_meta.json."""
    cache_file = Path(raw_dir) / "registry_meta.json"
    cache = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}
    todo = [(n, v) for n, v in pkgs if f"{n}@{v}" not in cache]

    def one(nv):
        n, v = nv
        try:
            doc = _get(f"{REGISTRY}/{urllib.parse.quote(n, safe='@')}/{urllib.parse.quote(v)}")
            dist = doc.get("dist", {})
            return f"{n}@{v}", {"integrity": dist.get("integrity"), "shasum": dist.get("shasum"),
                                "attestations": bool(dist.get("attestations")),
                                "provenance": (dist.get("attestations") or {}).get("provenance", {}).get("predicateType"),
                                "scripts": {k: doc.get("scripts", {}).get(k) for k in SCRIPT_KEYS if doc.get("scripts", {}).get(k)},
                                "deprecated": doc.get("deprecated"), "publisher": (doc.get("_npmUser") or {}).get("name"),
                                "url": f"{REGISTRY}/{n}/{v}"}
        except Exception as err:
            return f"{n}@{v}", {"error": f"{type(err).__name__}: {err}"[:200]}
    if todo:
        with ThreadPoolExecutor(max_workers=12) as pool:
            for key, meta in pool.map(one, todo):
                cache[key] = meta
        cache_file.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    return cache


def _script_kind(text: str) -> str:
    if RISKY.search(text):
        return "risky"
    if TELEMETRY.search(text):
        return "telemetry"
    if NATIVE.search(text):
        return "native-build"
    if DOWNLOAD.search(text):
        return "download"
    return "other"


SCRIPT_VERDICT = {
    "risky": ("Suspicious", "high", "The install script uses patterns common in malicious packages (eval, encoded payloads, "
                                    "spawning shells or reading credentials)."),
    "telemetry": ("Needs review", "medium", "The install script reports back to a third party when the package is installed. "
                                            "It is not malware, but it sends data from your build machine without asking."),
    "download": ("Needs review", "medium", "The install script downloads or unpacks a binary at install time. That binary is "
                                           "not covered by the lockfile's integrity hash, so it is a provenance gap."),
    "native-build": ("Expected", "low", "The install script compiles native code (normal for database or XML drivers), "
                                        "but it still runs arbitrary build commands on the machine."),
    "other": ("Needs review", "medium", "The install script runs code we could not classify; read it before allowing it."),
}
SCRIPT_REMEDY = {
    "risky": "Block the package: remove it, install with --ignore-scripts, and report it to npm security if confirmed.",
    "telemetry": "Disable the telemetry (for Scarf: add \"scarfSettings\": {\"enabled\": false} to package.json, or set "
                 "SCARF_ANALYTICS=false) or install with --ignore-scripts.",
    "download": "Pin the binary version, verify its checksum, and build with --ignore-scripts in CI, allowing scripts only "
                "for packages you have reviewed.",
    "native-build": "Allow-list it explicitly (e.g. npm's --ignore-scripts plus a reviewed rebuild step) and keep it updated.",
    "other": "Read the script before installing; install with --ignore-scripts until reviewed.",
}


def _path_to(graph: dict, label: str) -> list:
    for n in graph.get("nodes", []):
        if n["label"] == label:
            return n.get("shortest_path", [])
    return []


def investigate(repo: Path, d1: dict, use_llm: bool = True, offline: bool = False) -> dict:
    out, repo = d1["out"], Path(repo)
    lock = json.loads((repo / "package-lock.json").read_text(encoding="utf-8"))
    pk = lock.get("packages", {})
    manifest = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    deps = d1["deps"]
    by_path = {d["lock_path"]: d for d in deps}
    items: list[Investigation] = []

    def add(**kw):
        items.append(Investigation(id=f"INV-{len(items) + 1:03d}", **kw))

    # ---- what to look up in the registry ----
    install_pkgs = [(p, v) for p, v in pk.items() if p and v.get("hasInstallScript")]
    direct_prod = [d for d in deps if d.get("type") == "direct" and d.get("scope") != "dev"]
    vuln_pkgs = {(f["package"], f["installed_version"]) for f in d1["vulns"]["findings"]}
    wanted = sorted({(by_path.get(p, {}).get("name") or p.split("node_modules/")[-1], v.get("version")) for p, v in install_pkgs}
                    | {(d["name"], d["version"]) for d in direct_prod} | vuln_pkgs)
    meta, reg_note = {}, ""
    if not offline:
        meta = registry_meta(wanted, out / "raw")
        ok = sum(1 for k in meta if "error" not in meta[k])
        reg_note = f"npm registry metadata read for {ok} of {len(wanted)} packages"

    # ---- 1. install scripts ----
    for lp, entry in install_pkgs:
        name = by_path.get(lp, {}).get("name") or lp.split("node_modules/")[-1]
        ver = entry.get("version")
        m = meta.get(f"{name}@{ver}", {})
        scripts = m.get("scripts") or {}
        text = " ; ".join(f"{k}: {v}" for k, v in scripts.items())
        kind = _script_kind(text) if text else "other"
        verdict, sev, why = SCRIPT_VERDICT[kind]
        scope = "dev" if entry.get("dev") else "optional" if entry.get("optional") else "prod"
        if scope != "prod" and verdict != "Suspicious":
            sev = "low"
        used = "development only" if entry.get("dev") else "production"
        ev = [{"fact": f"package-lock.json marks {name}@{ver} with hasInstallScript: true", "source": f"package-lock.json → {lp}"},
              {"fact": f"Used in: {used}" + (", optional (only installed on some platforms)" if entry.get("optional") else ""),
               "source": "package-lock.json"}]
        if text:
            ev.append({"fact": f"Install script published on npm: {text[:300]}", "source": m.get("url", REGISTRY)})
        elif m.get("error"):
            ev.append({"fact": f"Registry lookup failed: {m['error']}", "source": REGISTRY})
        path = _path_to(d1["graph"], f"{name}@{ver}")
        if path:
            ev.append({"fact": "Reaches the app through " + " → ".join(path), "source": "dependency graph (Agent 3)"})
        add(category="install-script", title=f"{name}@{ver} runs code when installed ({kind.replace('-', ' ')})",
            subject=f"{name}@{ver}", verdict=verdict, severity=sev, verified_evidence=ev, inference=why,
            inference_source="rule-based inference (pattern match on the script text)", remedy=SCRIPT_REMEDY[kind])

    # ---- 2. provenance and integrity of every locked package ----
    hosts, no_integrity, sha1_only, git_like = {}, [], [], []
    for p, v in pk.items():
        if not p or v.get("link"):
            continue
        r = v.get("resolved") or ""
        if r.startswith(("git", "github:", "file:")) or "codeload.github.com" in r:
            git_like.append(f"{p.split('node_modules/')[-1]} ← {r[:80]}")
        h = urlparse(r).hostname if r.startswith("http") else ("(git/file)" if r else "(bundled)")
        hosts[h] = hosts.get(h, 0) + 1
        integ = v.get("integrity") or ""
        if not integ and not v.get("inBundle"):
            no_integrity.append(p.split("node_modules/")[-1])
        elif integ.startswith("sha1-"):
            sha1_only.append(p.split("node_modules/")[-1])
    third = {h: n for h, n in hosts.items() if h not in ("registry.npmjs.org", "(bundled)")}
    ev = [{"fact": "Download sources in the lockfile: " + ", ".join(f"{h} ({n})" for h, n in sorted(hosts.items(), key=lambda x: -x[1])),
           "source": "package-lock.json resolved fields"},
          {"fact": f"{len(no_integrity)} packages have no integrity hash; {len(sha1_only)} only have a SHA-1 hash", "source": "package-lock.json integrity fields"}]
    if git_like:
        ev.append({"fact": "Installed straight from git or a file instead of the registry: " + "; ".join(git_like[:5]), "source": "package-lock.json"})
    bad = bool(third or git_like or no_integrity)
    add(category="provenance", title="Where every package is downloaded from" + (" — non-registry sources found" if bad else ""),
        subject="package-lock.json", verdict="Needs review" if bad else "Expected", severity="medium" if bad else "info",
        verified_evidence=ev,
        inference=("Packages from git URLs, other hosts or without integrity hashes bypass the registry's checks, so a changed "
                   "upstream repo or a compromised host could swap the code without the lockfile noticing.") if bad else
                  ("Every package comes from the official npm registry with a SHA-512 integrity hash, so npm will refuse "
                   "any download whose bytes differ from what was locked."),
        inference_source="rule-based inference", remedy=("Replace git/URL dependencies with registry releases and regenerate "
                                                         "the lockfile so every entry has a sha512 integrity hash.") if bad else "No action needed; keep using npm ci so integrity is enforced.")

    if meta:
        # ---- 3. integrity: lockfile vs registry ----
        checked, mismatch = 0, []
        for p, v in pk.items():
            if not p:
                continue
            name = by_path.get(p, {}).get("name") or p.split("node_modules/")[-1]
            m = meta.get(f"{name}@{v.get('version')}")
            if m and m.get("integrity") and v.get("integrity"):
                checked += 1
                if m["integrity"] != v["integrity"]:
                    mismatch.append(f"{name}@{v.get('version')}")
        add(category="integrity", title=("Lockfile hashes differ from the registry" if mismatch else
                                         f"Lockfile hashes match the registry ({checked} packages checked)"),
            subject="package-lock.json", verdict="Suspicious" if mismatch else "Expected",
            severity="critical" if mismatch else "info",
            verified_evidence=[{"fact": f"Compared the integrity hash of {checked} locked packages with the hash the npm registry publishes", "source": REGISTRY},
                               {"fact": (f"{len(mismatch)} mismatch: " + ", ".join(mismatch[:8])) if mismatch else "0 mismatches", "source": "package-lock.json vs registry"}],
            inference=("A hash that differs from the registry means the lockfile points at different bytes than the published "
                       "release: either the lockfile was edited or the package came from somewhere else.") if mismatch else
                      "The locked bytes are exactly what the registry published for these versions; no sign of lockfile tampering.",
            inference_source="rule-based inference",
            remedy="Delete the affected entries, regenerate the lockfile from the registry and investigate who changed it." if mismatch else "No action needed.")

        # ---- 4. build provenance (SLSA attestations on npm) ----
        att = [d for d in direct_prod if meta.get(f"{d['name']}@{d['version']}", {}).get("attestations")]
        missing = [f"{d['name']}@{d['version']}" for d in direct_prod
                   if f"{d['name']}@{d['version']}" in meta and "error" not in meta[f"{d['name']}@{d['version']}"]
                   and not meta[f"{d['name']}@{d['version']}"].get("attestations")]
        add(category="provenance-attestation",
            title=f"{len(missing)} of {len(att) + len(missing)} production dependencies have no build provenance",
            subject="package.json", verdict="Needs review" if missing else "Expected", severity="low",
            verified_evidence=[{"fact": f"{len(att)} direct production dependencies publish an npm provenance attestation (built by CI from a known repo)", "source": REGISTRY},
                               {"fact": "Without attestation: " + ", ".join(missing[:15]) + ("…" if len(missing) > 15 else ""), "source": REGISTRY}],
            inference=("A package without provenance was uploaded from someone's machine, so nobody can prove the tarball "
                       "matches the source repository. That is normal for older packages, but it is the gap attackers use "
                       "when they steal a maintainer's npm token."),
            inference_source="rule-based inference",
            remedy="Prefer versions with provenance when upgrading; for critical packages, compare the tarball with the tagged source.")

        # ---- 5. deprecated packages ----
        dep_list = [(k, v["deprecated"]) for k, v in meta.items() if v.get("deprecated") and k in {f"{n}@{v_}" for n, v_ in wanted}]
        if dep_list:
            add(category="deprecated", title=f"{len(dep_list)} installed packages are deprecated by their maintainers",
                subject="npm registry", verdict="Needs review", severity="medium",
                verified_evidence=[{"fact": f"{k}: \"{msg[:140]}\"", "source": f"{REGISTRY}/{k.rsplit('@', 1)[0]}"} for k, msg in dep_list[:10]],
                inference="Deprecated packages no longer get security fixes, so any future vulnerability in them stays open (CWE-1104).",
                inference_source="rule-based inference", remedy="Replace each with the alternative its maintainer recommends in the deprecation message.")

    # ---- 6. loose ranges in package.json ----
    loose = []
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for n, rng in (manifest.get(sec) or {}).items():
            r = str(rng).strip()
            if r in ("*", "latest", "x", "") or r.startswith((">=", ">")) or "://" in r or r.startswith(("git", "github:")):
                loose.append(f"{n}: \"{r}\" ({sec})")
    if loose:
        add(category="loose-range", title=f"{len(loose)} dependencies accept any future version",
            subject="package.json", verdict="Needs review", severity="medium",
            verified_evidence=[{"fact": l, "source": "package.json"} for l in loose[:12]],
            inference="An unbounded range lets the next published release in automatically; if that release is malicious "
                      "(a hijacked maintainer account), a fresh install picks it up.",
            inference_source="rule-based inference", remedy="Use a caret or exact range and rely on the lockfile; review upgrades deliberately.")

    # ---- 7. manifest vs lockfile ----
    dnl = d1["inventory"].get("declared_not_locked", [])
    add(category="manifest-lockfile", title=("package.json and the lockfile disagree" if dnl else "package.json and the lockfile agree"),
        subject="package.json ↔ package-lock.json", verdict="Needs review" if dnl else "Expected", severity="medium" if dnl else "info",
        verified_evidence=[{"fact": f"{len(direct_prod)} production and {sum(1 for d in deps if d.get('type') == 'direct' and d.get('scope') == 'dev')} development dependencies declared", "source": "package.json"},
                           {"fact": ("Declared but not in the lockfile: " + ", ".join(dnl[:10])) if dnl else "Every declared dependency is locked", "source": "package-lock.json"}],
        inference=("A dependency declared but not locked will be resolved fresh on install, so different machines can get "
                   "different code.") if dnl else "Installs are reproducible: every declared dependency is pinned by the lockfile.",
        inference_source="rule-based inference", remedy="Regenerate the lockfile and commit it." if dnl else "No action needed.")

    # ---- 8. Day 1 anomalies: each change since the baseline on its own, standing observations grouped ----
    base = d1["suspicious"].get("base_ref", "HEAD")
    standing = {}
    for f in d1["suspicious"].get("findings", []):
        if f["category"] == "lifecycle_script":
            continue  # covered in detail above
        if f["kind"] != "change":
            standing.setdefault(f["category"], []).append(f)
            continue
        ev = [{"fact": f["title"], "source": f["file"]},
              {"fact": f"Before: {f.get('before') or '(not present)'} → After: {f.get('after') or '(not present)'}",
               "source": f"git diff {base} → working tree"}]
        e = f.get("evidence") or {}
        if isinstance(e, dict) and e:
            ev.append({"fact": "; ".join(f"{k}: {v if not isinstance(v, list) else ', '.join(map(str, v[:8]))}" for k, v in e.items())[:400],
                       "source": "Agent 5 evidence"})
        add(category=f["category"], title=f["title"], subject=f["file"],
            verdict="Suspicious" if f["severity"] in ("critical", "high") else "Needs review", severity=f["severity"],
            verified_evidence=ev, inference=f["why_suspicious"], inference_source="rule-based inference (Agent 5 rule)",
            remedy=f.get("remediation", ""), day1_ref=f["id"])
    for cat, group in standing.items():
        first = group[0]
        if cat == "unpinned_container_image":
            title = f"{len(group)} container images are referenced by tag, not by digest"
            facts = [{"fact": f"{g['after']} ({(g.get('evidence') or {}).get('pinning', 'tag')})", "source": g["file"]} for g in group]
        else:
            title = first["title"]
            e = first.get("evidence") or {}
            facts = [{"fact": first["title"], "source": first["file"]}] + (
                [{"fact": ", ".join(map(str, v)), "source": first["file"]} for v in e.values() if isinstance(v, list)][:1])
        add(category=cat, title=title, subject=", ".join(sorted({g["file"] for g in group}))[:120], verdict="Needs review",
            severity=max((g["severity"] for g in group), key=lambda s: ["info", "low", "medium", "high", "critical"].index(s)
                         if s in ["info", "low", "medium", "high", "critical"] else 0),
            verified_evidence=facts, inference=first["why_suspicious"] + (
                " A tag such as 'latest' or '24' can be moved to a different image at any time, so two builds of the same "
                "commit may ship different operating-system packages." if cat == "unpinned_container_image" else ""),
            inference_source="rule-based inference (Agent 5 rule)", remedy=first.get("remediation", ""),
            day1_ref=", ".join(g["id"] for g in group))

    if use_llm:
        from guardian.day2 import reasoning
        todo = [i for i in items if i.verdict != "Expected"]
        res = reasoning.explain(out, "For each supply-chain observation (not a CVE), explain what it could mean for this "
                                     "application, how an attacker could abuse it, whether the evidence looks malicious, "
                                     "risky-but-normal, or benign, and what a reviewer should check first.",
                                [{"id": i.id, "evidence": {"title": i.title, "subject": i.subject, "category": i.category,
                                                           "facts": i.verified_evidence, "verdict": i.verdict}} for i in todo],
                                {i.id: i.inference for i in todo})
        for i in todo:
            if res[i.id]["source"].startswith("AI"):
                i.inference, i.inference_source = res[i.id]["text"], res[i.id]["source"]

    order = {"Suspicious": 0, "Needs review": 1, "Expected": 2}
    sev = ["critical", "high", "medium", "moderate", "low", "info"]
    items.sort(key=lambda i: (order[i.verdict], sev.index(i.severity) if i.severity in sev else 9))
    for k, i in enumerate(items, 1):
        i.id = f"INV-{k:03d}"
    data = {"registry": reg_note or "registry lookups skipped (offline)", "items": [i.model_dump() for i in items]}
    write_json(day2_dir(out) / "investigations.json", data)
    return data
