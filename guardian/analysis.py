"""Derived views shared by the dashboard and the PDF report (computed only from scan outputs)."""
from collections import Counter
from urllib.parse import urlparse

SEVERITIES = ["critical", "high", "moderate", "medium", "low", "info", "unknown"]
GRADES = [(90, "A", "Cleared"), (75, "B", "Cleared with notes"), (60, "C", "Inspect before shipping"),
          (40, "D", "Hold for review"), (0, "F", "Do not ship")]
LICENCE_GROUPS = [
    ("Strong copyleft", ("AGPL", "GPL", "CC-BY-SA", "EUPL", "SSPL", "OSL")),
    ("Weak copyleft", ("LGPL", "MPL", "EPL", "CDDL", "CPL")),
    ("Permissive", ("MIT", "ISC", "APACHE", "BSD", "0BSD", "BLUEOAK", "UNLICENSE", "CC0", "PYTHON", "ZLIB",
                    "WTFPL", "ARTISTIC", "CC-BY", "OFL", "BOOST", "X11")),
]


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)


def risk_grade(findings: list, changes: list, inventory: dict):
    """Start at 100, subtract points per real finding. Returns (score, letter, verdict, breakdown rows)."""
    rows = []

    def add(factor, count, each):
        if count:
            rows.append({"factor": factor, "count": int(count), "points each": each, "deducted": round(count * each, 1)})
    prod = [f for f in findings if f["scope"] == "prod"]
    dev = [f for f in findings if f["scope"] != "prod"]
    add("Critical advisories in shipped packages", sum(f["severity"] == "critical" for f in prod), 15)
    add("High advisories in shipped packages", sum(f["severity"] == "high" for f in prod), 6)
    add("Moderate advisories in shipped packages", sum(f["severity"] in ("moderate", "medium") for f in prod), 2)
    add("Low advisories in shipped packages", sum(f["severity"] == "low" for f in prod), 0.5)
    add("Critical/high advisories in dev-only packages", sum(f["severity"] in ("critical", "high") for f in dev), 1)
    add("Critical/high changes since baseline", sum(c["severity"] in ("critical", "high") for c in changes), 10)
    add("Medium changes since baseline", sum(c["severity"] == "medium" for c in changes), 4)
    comps = inventory.get("components", [])
    docker = [c for c in comps if c["ecosystem"] == "docker"]
    actions = [c for c in comps if c["ecosystem"] == "github-actions"]
    add("Container images without a digest pin", int(any(c["pinning"] != "digest" for c in docker)), 4)
    add("CI actions without a commit-SHA pin", int(any(c["pinning"] != "sha" for c in actions)), 2)
    score = max(0.0, 100 - sum(r["deducted"] for r in rows))
    letter, verdict = next((l, v) for limit, l, v in GRADES if score >= limit)
    return round(score), letter, verdict, rows


def licence_group(lic) -> str:
    if lic is None or (isinstance(lic, float)) or not str(lic).strip():
        return "Not declared"
    u = str(lic).upper()
    if u in ("NONE", "UNLICENSED") or "SEE LICENSE" in u:
        return "Not declared"
    for name, keys in LICENCE_GROUPS:
        if any(u.startswith(k) or f"({k}" in u or f" {k}" in u for k in keys):
            return name
    return "Other"


def origins(deps: list) -> list[tuple[str, int]]:
    """Where installed packages are downloaded from (host of the lockfile's resolved URL)."""
    hosts = Counter()
    for d in deps:
        r = d.get("resolved") or ""
        if not r:
            hosts["not recorded (bundled or linked)"] += 1
        elif r.startswith(("git", "github:")):
            hosts["git source"] += 1
        else:
            hosts[urlparse(r).hostname or r] += 1
    return hosts.most_common()


def checkpoint(report: dict, inventory: dict, vulns: dict, susp: dict) -> dict:
    """The Day 1 checkpoint: what is in it, what changed, what appears risky."""
    m, s = report["metrics"], inventory["summary"]
    changes = [f for f in susp["findings"] if f["kind"] == "change"]
    sev = m["vulnerabilities_by_severity"]
    pkgs = len({(f["package"], f["installed_version"]) for f in vulns["findings"]})
    inside = (f"{s['npm_packages']} npm packages ({s['direct']} chosen in package.json, {s['transitive']} pulled in), "
              f"{s['container_images']} container image references and {s['ci_actions']} CI action references, "
              f"found in {len(inventory['manifests'])} manifest files.")
    changed = (f"{len(changes)} supply-chain change{'s' if len(changes) != 1 else ''} since baseline {susp['base_ref']}"
               + (": " + "; ".join(c["title"] for c in changes[:3]) + ("…" if len(changes) > 3 else "") + "." if changes
                  else ". Manifests, lockfile, Dockerfiles and CI workflows match the baseline."))
    risky = (f"{m['vulnerabilities']} known advisories in {pkgs} installed packages "
             f"({sev.get('critical', 0)} critical, {sev.get('high', 0)} high); {m['vulnerable_prod']} affect shipped code. "
             f"{sum(1 for f in susp['findings'] if f['kind'] == 'baseline')} standing supply-chain observations.")
    return {"inside": inside, "changed": changed, "risky": risky}
