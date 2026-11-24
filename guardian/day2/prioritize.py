"""Agent 6 - Risk Analysis, part 1: prioritisation.

Score = severity (40) + exploitability (25) + reachability (20) + exposure (15) = 0-100.
Every point comes with a one-line reason built from evidence, so the score can be explained and checked.
Confidence says how much of that evidence was actually available (not guessed).
"""
import json
from collections import defaultdict
from pathlib import Path

from guardian.day2 import cwe as cwe_mod
from guardian.day2 import exploit, reachability
from guardian.day2.common import day2_dir, write_json
from guardian.models import FactorScore, RiskItem

SEV_SCORE = {"critical": 9.5, "high": 8.0, "moderate": 5.5, "medium": 5.5, "low": 2.5, "info": 1.0, "unknown": 5.0}
TIERS = [(80, "Critical"), (65, "High"), (45, "Medium"), (0, "Low")]
SEV_ORDER = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]


def tier_of(score: float) -> str:
    return next(t for limit, t in TIERS if score >= limit)


def confidence_label(c: float) -> str:
    return "High" if c >= 0.8 else "Medium" if c >= 0.6 else "Low"


def severity_factor(f: dict) -> FactorScore:
    if f.get("cvss"):
        s = float(f["cvss"])
        why = f"CVSS {s:.1f} ({f['severity']}) published with the advisory"
    else:
        s = SEV_SCORE.get(f["severity"], 5.0)
        why = f"no CVSS score published; '{f['severity']}' rating counted as {s}"
    return FactorScore(factor="severity", points=round(s * 4, 1), max_points=40, reason=why)


def exploit_factor(f: dict, ex: dict) -> tuple[FactorScore, bool]:
    ids = [f["id"]] + list(f.get("aliases") or [])
    mapped = (ex.get("ghsa_cve") or {}).get(f["id"])
    if mapped:
        ids.append(mapped)
    for i in ids:
        if i in ex.get("kev", {}):
            return FactorScore(factor="exploitability", points=25, max_points=25,
                               reason=f"{i} is in CISA's Known Exploited Vulnerabilities list: attacked in the wild"), True
    for i in ids:
        e = ex.get("epss", {}).get(i)
        if e:
            pts = round(5 + 20 * e["percentile"], 1)
            return FactorScore(factor="exploitability", points=pts, max_points=25,
                               reason=f"EPSS {e['epss'] * 100:.2f}% chance of exploitation in 30 days "
                                      f"(higher than {e['percentile'] * 100:.0f}% of all CVEs)"), True
    v = exploit.parse_vector(f.get("cvss_vector"))
    if v:
        # the vector describes what is theoretically possible, so it can earn at most 18 of 25;
        # only real-world data (EPSS, KEV) can push exploitability to the top
        pts = 4 + (6 if v.get("AV") == "N" else 3 if v.get("AV") == "A" else 0) + (3 if v.get("AC") == "L" else 0) \
              + (3 if v.get("PR") == "N" else 1 if v.get("PR") == "L" else 0) + (2 if v.get("UI") == "N" else 0)
        bits = [exploit.AV.get(v.get("AV"), "unknown access"),
                "low complexity" if v.get("AC") == "L" else "high complexity",
                "no login needed" if v.get("PR") == "N" else "needs a login",
                "no user interaction" if v.get("UI") == "N" else "needs a user to act"]
        return FactorScore(factor="exploitability", points=pts, max_points=25,
                           reason="CVSS vector: exploitable " + ", ".join(bits)), True
    return FactorScore(factor="exploitability", points=12, max_points=25,
                       reason="no exploit data or CVSS vector published; assumed moderate"), False


REACH_POINTS = {"imported": 20, "via-import": 14, "not-imported": 6, "dev": 2}


def reach_factor(r: dict) -> FactorScore:
    return FactorScore(factor="reachability", points=REACH_POINTS[r["level"]], max_points=20, reason=r["label"])


def exposure_factor(scope: str, network: bool) -> FactorScore:
    if scope == "dev":
        return FactorScore(factor="exposure", points=3, max_points=15, reason="not shipped: development dependency")
    if network:
        return FactorScore(factor="exposure", points=15, max_points=15,
                           reason="shipped in production in an internet-facing web server")
    return FactorScore(factor="exposure", points=10, max_points=15, reason="shipped in production")


def rule_reasoning(pkg: str, ver: str, advs: list, reach: dict, factors: list, tier: str) -> str:
    worst = advs[0]
    cwes = cwe_mod.describe(worst.get("cwe"))
    what = cwes[0][2] if cwes and cwes[0][1] != "see the advisory" else "the advisory describes the impact"
    f = {x.factor: x for x in factors}
    title = worst["title"] if len(worst["title"]) <= 110 else worst["title"][:110].rsplit(" ", 1)[0] + "…"
    s = (f"{pkg}@{ver} is rated {tier} because its worst advisory ({worst['id']}: {title}) means {what}. "
         f"{f['exploitability'].reason[0].upper() + f['exploitability'].reason[1:]}. "
         f"It is {reach['label']}, and {f['exposure'].reason}.")
    if len(advs) > 1:
        s += f" {len(advs) - 1} more advisor{'y affects' if len(advs) == 2 else 'ies affect'} the same version."
    return s


def prioritise(repo: Path, d1: dict, use_llm: bool = True) -> dict:
    out = d1["out"]
    findings = d1["vulns"]["findings"]
    imports = reachability.scan_imports(repo)
    direct_names = {d["name"] for d in d1["deps"] if d.get("type") == "direct" and d.get("scope") != "dev"}
    literals = reachability.literal_refs(repo, {n for n in direct_names if n not in imports})
    network = reachability.is_network_service(repo, imports)
    ex = exploit.load(findings, out / "raw")
    nodes = {n["label"]: n for n in d1["graph"].get("nodes", [])}

    groups = defaultdict(list)
    for f in findings:
        groups[(f["package"], f["installed_version"])].append(f)

    items = []
    for (pkg, ver), advs in groups.items():
        advs.sort(key=lambda a: (SEV_ORDER.index(a["severity"]) if a["severity"] in SEV_ORDER else 9, -(a.get("cvss") or 0)))
        scored = []
        for a in advs:
            sf = severity_factor(a)
            ef, has_ex = exploit_factor(a, ex)
            scored.append((sf.points + ef.points, sf, ef, has_ex, a))
        scored.sort(key=lambda x: -x[0])
        _, sf, ef, has_ex, worst = scored[0]
        scope = "prod" if any(a["scope"] == "prod" for a in advs) else advs[0]["scope"]
        direct = any(a["direct"] for a in advs)
        via = sorted({v for a in advs for v in a.get("introduced_via", [])})
        r = reachability.reachability(pkg, direct, scope, via, imports, literals)
        factors = [sf, ef, reach_factor(r), exposure_factor(scope, network)]
        score = round(sum(x.points for x in factors), 1)
        conf, why = 0.4, []
        if worst.get("cvss_vector"):
            conf += 0.2
            why.append("CVSS vector published")
        else:
            why.append("no CVSS vector: severity taken from the rating")
        if "EPSS" in ef.reason or "Known Exploited" in ef.reason:
            conf += 0.15
            why.append("real-world exploit data (EPSS/KEV) available")
        else:
            why.append("no EPSS/KEV data: exploitability estimated from the vector")
        if r["decided"]:
            conf += 0.15
            why.append("reachability confirmed from source imports" if r["level"] != "dev" else "dev-only scope confirmed from lockfile")
        else:
            why.append("no import found; package could still be loaded dynamically")
        if any(a.get("fixed_version") for a in advs) or worst.get("dependency_path"):
            conf += 0.1
            why.append("dependency path traced in the graph")
        conf = round(min(conf, 0.99), 2)
        tier = tier_of(score)
        node = nodes.get(f"{pkg}@{ver}")
        items.append(RiskItem(
            id="", kind="vulnerability", subject=f"{pkg}@{ver}", package=pkg, version=ver,
            lock_path=node["id"] if node else None, advisories=[a["id"] for a in advs],
            worst_severity=worst["severity"], score=score, tier=tier, factors=factors, confidence=conf,
            confidence_label=confidence_label(conf), confidence_reasons=why,
            evidence={"package": f"{pkg}@{ver}", "direct": direct, "scope": scope, "introduced_via": via,
                      "dependency_path": worst.get("dependency_path", []), "reachability": r,
                      "advisories": [{"id": a["id"], "aliases": a.get("aliases", []), "severity": a["severity"],
                                      "cvss": a.get("cvss"), "cvss_vector": a.get("cvss_vector"), "cwe": a.get("cwe", []),
                                      "title": a["title"], "fixed_version": a.get("fixed_version"),
                                      "reference": a.get("reference")} for a in advs],
                      "cwe_meaning": [{"cwe": c, "name": n, "impact": i} for c, n, i in cwe_mod.describe(worst.get("cwe"))],
                      "exploitability": ef.reason},
            reasoning=rule_reasoning(pkg, ver, [s[4] for s in scored], r, factors, tier),
            reasoning_source="rule-based reasoning (no LLM)"))

    items.sort(key=lambda i: (-i.score, i.subject))
    for k, it in enumerate(items, 1):
        it.id = f"RISK-{k:03d}"

    if use_llm:
        from guardian.day2 import reasoning
        top = items[:15]
        res = reasoning.explain(out, "Explain why each vulnerable package is (or is not) urgent for THIS application: "
                                     "what an attacker could do (from the CWE meaning and advisory title), how exploitable it "
                                     "is, whether the app's code can reach it, and its exposure. End with the single most "
                                     "important reason.",
                                [{"id": i.id, "evidence": {**i.evidence, "score": i.score, "tier": i.tier,
                                                           "factors": [f.model_dump() for f in i.factors]}} for i in top],
                                {i.id: i.reasoning for i in top})
        for i in top:
            i.reasoning, i.reasoning_source = res[i.id]["text"], res[i.id]["source"]

    data = {"exploitability_notes": ex.get("notes", []), "network_service": network,
            "imports_scanned": len(imports), "method": {
                "severity": "CVSS base score x 4 (max 40); rating mapped when no CVSS",
                "exploitability": "CISA KEV = 25; else EPSS percentile (5-25); else CVSS vector AV/AC/PR/UI (4-18); else 12",
                "reachability": "imported by app code 20; via an imported dependency 14; shipped but not imported 6; dev only 2",
                "exposure": "production + web server 15; production 10; development 3",
                "tiers": "Critical >= 80, High >= 65, Medium >= 45, Low < 45"},
            "items": [i.model_dump() for i in items]}
    write_json(day2_dir(out) / "risk_priorities.json", data)
    return data


# ---------------- supply-chain (non-CVE) risks from the investigation ----------------
SC_SEV = {"critical": 38, "high": 32, "medium": 22, "moderate": 22, "low": 12, "info": 4}


def add_supply_chain(out: Path, risks: dict, invs: dict) -> dict:
    """Score the investigated non-CVE risks on the same 0-100 scale so one queue holds everything."""
    items = [RiskItem(**i) for i in risks["items"] if i["kind"] == "vulnerability"]
    for inv in invs["items"]:
        if inv["verdict"] == "Expected":
            continue
        cat, text = inv["category"], inv["title"].lower()
        prod = "production" in json.dumps(inv["verified_evidence"]) or cat not in ("install-script",)
        if inv["verdict"] == "Suspicious":
            ex = FactorScore(factor="exploitability", points=20, max_points=25, reason="the change matches a known attack pattern")
        elif cat == "install-script":
            ex = FactorScore(factor="exploitability", points=14, max_points=25,
                             reason="code runs automatically on every npm install, with the installing user's rights")
        elif cat in ("unpinned_container_image", "unexpected_ci_dependency"):
            ex = FactorScore(factor="exploitability", points=12, max_points=25,
                             reason="a mutable tag can be repointed by whoever controls the upstream image or action")
        else:
            ex = FactorScore(factor="exploitability", points=8, max_points=25, reason="indirect: weakens the ability to detect tampering")
        if cat == "install-script":
            rc = FactorScore(factor="reachability", points=20 if prod else 10, max_points=20,
                             reason="runs on every production install" if prod else "runs on developer and CI machines")
        elif cat == "unpinned_container_image":
            rc = FactorScore(factor="reachability", points=15, max_points=20, reason="decides what goes into the shipped container")
        elif cat == "unexpected_ci_dependency":
            rc = FactorScore(factor="reachability", points=12, max_points=20, reason="runs in CI with the repository's token")
        else:
            rc = FactorScore(factor="reachability", points=10, max_points=20, reason="affects how packages are trusted")
        expo = FactorScore(factor="exposure", points=12 if prod else 6, max_points=15,
                           reason="build and release pipeline" if prod else "development machines only")
        sv = FactorScore(factor="severity", points=SC_SEV.get(inv["severity"], 12), max_points=40,
                         reason=f"{inv['verdict']} ({inv['severity']}) from the investigation")
        factors = [sv, ex, rc, expo]
        score = round(sum(f.points for f in factors), 1)
        items.append(RiskItem(
            id="", kind="supply-chain", subject=inv["title"], advisories=[], worst_severity=inv["severity"], score=score,
            tier=tier_of(score), factors=factors, confidence=0.75 if inv["verdict"] != "Needs review" else 0.65,
            confidence_label=confidence_label(0.75 if inv["verdict"] != "Needs review" else 0.65),
            confidence_reasons=["facts verified from files/registry", "impact is a judgement: no CVSS exists for non-CVE risks"],
            evidence={"investigation": inv["id"], "category": cat, "facts": inv["verified_evidence"]},
            reasoning=inv["inference"], reasoning_source=inv["inference_source"]))
    items.sort(key=lambda i: (-i.score, i.subject))
    for k, it in enumerate(items, 1):
        it.id = f"RISK-{k:03d}"
    risks = {**risks, "items": [i.model_dump() for i in items]}
    write_json(day2_dir(out) / "risk_priorities.json", risks)
    return risks
