"""Day 2 tests: scoring, reachability, approvals and audit trail, validation helpers, LLM guard, benchmark."""
import json
import subprocess
from pathlib import Path

import pytest

from guardian import benchmark
from guardian.day2 import approvals, prioritize, reachability, reasoning, validate
from guardian.day2.common import audit, read_audit, verify_audit

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


# ---------------- audit trail ----------------
def test_audit_chain_detects_tampering(tmp_path):
    for i in range(3):
        audit(tmp_path, "tester", "event", {"i": i})
    assert verify_audit(tmp_path)[0]
    log = tmp_path / "day2" / "audit_log.jsonl"
    lines = log.read_text().splitlines()
    e = json.loads(lines[1])
    e["details"]["i"] = 99  # someone edits history
    lines[1] = json.dumps(e)
    log.write_text("\n".join(lines) + "\n")
    ok, msg = verify_audit(tmp_path)
    assert not ok and "entry 1" in msg


# ---------------- approvals ----------------
def _plan(tmp_path, actions):
    from guardian.day2.remediate import action_hash
    for a in actions:
        a["hash"] = action_hash(a)
    (tmp_path / "day2").mkdir(exist_ok=True)
    (tmp_path / "day2" / "remediation_plan.json").write_text(json.dumps({"actions": actions}))


def _action(aid, auto=True, target="x"):
    return {"id": aid, "type": "upgrade", "title": f"Upgrade {target}", "covers_packages": [f"{target}@1.0.0"],
            "changes": [{"file": "package.json", "op": "set-dependency", "target": target, "value": "2.0.0"}] if auto else [],
            "auto_applicable": auto}


def test_decisions_need_a_named_reviewer_and_reasons(tmp_path):
    _plan(tmp_path, [_action("ACT-001"), _action("ACT-002", auto=False, target="y")])
    with pytest.raises(ValueError, match="reviewer"):
        approvals.decide(tmp_path, "ACT-001", "approve", "  ")
    with pytest.raises(ValueError, match="reason"):
        approvals.decide(tmp_path, "ACT-001", "reject", "Rohit", "")
    with pytest.raises(ValueError, match="review date"):
        approvals.decide(tmp_path, "ACT-002", "accept-risk", "Rohit", "demo only")
    with pytest.raises(ValueError, match="no automatic change"):
        approvals.decide(tmp_path, "ACT-002", "approve", "Rohit")
    approvals.decide(tmp_path, "ACT-001", "approve", "Rohit")
    assert [a["id"] for a in approvals.approved_actions(tmp_path)] == ["ACT-001"]
    assert any(e["event"] == "decision" and e["actor"] == "human:Rohit" for e in read_audit(tmp_path))


def test_decision_follows_the_change_not_the_id(tmp_path):
    _plan(tmp_path, [_action("ACT-001", target="a"), _action("ACT-002", target="b")])
    approvals.decide(tmp_path, "ACT-002", "approve", "Rohit")
    _plan(tmp_path, [_action("ACT-001", target="b"), _action("ACT-002", target="a")])  # plan regenerated, ids swapped
    assert [a["title"] for a in approvals.approved_actions(tmp_path)] == ["Upgrade b"]
    _plan(tmp_path, [{**_action("ACT-001", target="b"), "changes": [{"file": "package.json", "op": "set-dependency",
                                                                     "target": "b", "value": "3.0.0"}]}])
    assert approvals.approved_actions(tmp_path) == []  # the change differs, so the old approval no longer applies


# ---------------- scoring and reachability ----------------
def test_severity_and_exploitability_factors():
    f = {"id": "GHSA-x", "aliases": ["CVE-2020-1"], "severity": "high", "cvss": 7.5,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
    assert prioritize.severity_factor(f).points == 30.0
    vec, has = prioritize.exploit_factor(f, {})
    assert has and vec.points == 18 and "network" in vec.reason
    kev, _ = prioritize.exploit_factor(f, {"kev": {"CVE-2020-1": {}}})
    assert kev.points == 25
    epss, _ = prioritize.exploit_factor(f, {"epss": {"CVE-2020-1": {"epss": 0.02, "percentile": 0.5}}})
    assert epss.points == 15.0
    none, has = prioritize.exploit_factor({"id": "GHSA-y", "severity": "moderate"}, {})
    assert not has and none.points == 12
    assert prioritize.tier_of(85) == "Critical" and prioritize.tier_of(44) == "Low"


def test_reachability_reads_imports_without_running_code(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "server.ts").write_text("import express from 'express'\nconst jwt = require('jsonwebtoken')\napp.set('view engine', 'hbs')")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "a.spec.ts").write_text("import chai from 'chai'")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text("{}")
    (tmp_path / "frontend" / "main.ts").write_text("import '@angular/core'")
    imp = reachability.scan_imports(tmp_path)
    assert imp["jsonwebtoken"]["runtime"] == ["server.ts"] and "test" in imp["chai"]
    assert "@angular/core" not in imp  # frontend has its own package.json
    assert reachability.is_network_service(tmp_path, imp)
    assert reachability.reachability("jsonwebtoken", True, "prod", [], imp)["level"] == "imported"
    assert reachability.reachability("jws", False, "prod", ["jsonwebtoken@0.4.0"], imp)["level"] == "via-import"
    lit = reachability.literal_refs(tmp_path, {"hbs"})
    assert reachability.reachability("hbs", True, "prod", [], imp, lit)["level"] == "imported"
    assert reachability.package_of("@scope/pkg/sub") == "@scope/pkg" and reachability.package_of("node:fs") is None


# ---------------- validation helpers ----------------
def test_parse_test_output_formats():
    tap = "ok 1 - a\nnot ok 2 - breaks login\n# tests 3\n# pass 2\n# fail 1\n# skipped 0\n"
    t = validate.parse_tests(tap)
    assert (t["passed"], t["failed"], t["failing"]) == (2, 1, ["breaks login"])
    assert validate.parse_tests("  12 passing (3s)\n  1 failing\n\n  1) api works:\n")["failed"] == 1
    assert validate.parse_tests("Tests:       2 failed, 40 passed, 42 total")["passed"] == 40


def test_apply_change_edits_only_the_requested_values(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}, indent=2))
    (tmp_path / "Dockerfile").write_text("FROM node:24\n")
    for c in [{"file": "package.json", "op": "set-dependency", "target": "a", "value": "^2.0.0", "section": "dependencies"},
              {"file": "package.json", "op": "add-override", "target": "b", "value": "3.1.0"},
              {"file": "package.json", "op": "set-json", "target": "scarfSettings.enabled", "value": "false"},
              {"file": "Dockerfile", "op": "replace-text", "target": "node:24", "value": "node:24@sha256:abc"}]:
        validate.apply_change(tmp_path, c, None)
    pkg = json.loads((tmp_path / "package.json").read_text())
    assert pkg == {"dependencies": {"a": "^2.0.0"}, "overrides": {"b": "3.1.0"}, "scarfSettings": {"enabled": False}}
    assert "node:24@sha256:abc" in (tmp_path / "Dockerfile").read_text()


def _case(build="pass", tests=("pass", 10, 0, []), smoke=()):
    return {"steps": [{"step": "Install (npm ci --ignore-scripts)", "status": "pass", "detail": ""},
                      {"step": "Build", "status": build, "detail": "run build"},
                      {"step": "Unit tests", "status": tests[0], "detail": ""}],
            "tests": {"passed": tests[1], "failed": tests[2], "failing": list(tests[3])}, "smoke": list(smoke)}


DIFF = {"resolved": [{"id": "GHSA-1"}], "new_vulnerabilities": [], "targeted_still_vulnerable": [], "new_install_scripts": []}


def test_verdict_compares_with_the_baseline():
    base = _case()
    assert validate.verdict(_case(), base, DIFF, [])[0] == "Verified"
    assert validate.verdict(_case(build="fail"), base, DIFF, [])[0] == "Failed validation"
    assert validate.verdict(_case(tests=("fail", 8, 2, ["login"])), base, DIFF, [])[0] == "Failed validation"
    # a test that already failed before the change is not blamed on the change
    flaky = _case(tests=("fail", 9, 1, ["flaky"]))
    assert validate.verdict(flaky, flaky, DIFF, [])[0] == "Verified"
    # a native module that can't load before or after is inconclusive, not a failure
    native = {"package": "sqlite3", "ok": False, "error": "bindings"}
    assert validate.verdict(_case(smoke=[native]), _case(smoke=[native]), DIFF, [])[0] == "Verified with notes"
    assert validate.verdict(_case(smoke=[native]), _case(smoke=[{**native, "ok": True}]), DIFF, [])[0] == "Failed validation"
    new_crit = {**DIFF, "new_vulnerabilities": [{"id": "GHSA-9", "severity": "critical"}]}
    assert validate.verdict(_case(), base, new_crit, [])[0] == "Failed validation"


# ---------------- LLM guard ----------------
def test_llm_answers_with_invented_ids_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(reasoning, "provider", lambda: {"kind": "test", "model": "fake"})
    monkeypatch.setattr(reasoning, "_call", lambda p, prompt: json.dumps({
        "RISK-001": "lodash@2.4.2 allows prototype pollution (GHSA-jf85-cpcp-j695).",
        "RISK-002": "Also see CVE-2099-12345 in lodash@9.9.9."}))
    items = [{"id": k, "evidence": {"package": "lodash@2.4.2", "id": "GHSA-jf85-cpcp-j695"}} for k in ("RISK-001", "RISK-002")]
    res = reasoning.explain(tmp_path, "explain", items, {"RISK-001": "rule 1", "RISK-002": "rule 2"})
    assert res["RISK-001"]["source"].startswith("AI inference")
    assert res["RISK-002"]["text"] == "rule 2" and "CVE-2099-12345" in res["RISK-002"]["rejected"]
    assert (tmp_path / "day2" / "llm_log.jsonl").exists()


def test_without_llm_everything_is_labelled_rule_based(tmp_path, monkeypatch):
    monkeypatch.setattr(reasoning, "provider", lambda: None)
    res = reasoning.explain(tmp_path, "x", [{"id": "A", "evidence": {}}], {"A": "rule"})
    assert res["A"] == {"text": "rule", "source": "rule-based reasoning (no LLM)", "rejected": []}


# ---------------- benchmark ----------------
def test_benchmark_parsers_and_consensus(tmp_path):
    grype = {"matches": [{"artifact": {"name": "lodash", "version": "2.4.2", "type": "npm"},
                          "vulnerability": {"id": "GHSA-jf85-cpcp-j695", "severity": "Critical", "fix": {"versions": ["4.17.12"]}},
                          "relatedVulnerabilities": [{"id": "CVE-2019-10744"}]},
                         {"artifact": {"name": "only-grype", "version": "1.0.0", "type": "npm"},
                          "vulnerability": {"id": "GHSA-zzzz-zzzz-zzzz", "severity": "Low", "fix": {}}}]}
    trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2019-10744", "PkgName": "lodash", "InstalledVersion": "2.4.2",
                                               "FixedVersion": "4.17.12", "Severity": "CRITICAL"}]}]}
    g, t = benchmark.parse_grype(grype), benchmark.parse_trivy(trivy)
    assert g[0]["ids"] == ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"] and t[0]["severity"] == "critical"
    results = {"grype": {"status": "ok", "findings": g, "raw_rows": 2},
               "trivy": {"status": "ok", "findings": t, "raw_rows": 1},
               "guardian": {"status": "ok", "findings": [{"package": "lodash", "version": "2.4.2", "ids": ["GHSA-jf85-cpcp-j695"],
                                                          "severity": "critical", "fixed": True, "path": True}], "raw_rows": 1}}
    s = benchmark.score_repo(tmp_path, results, benchmark.Aliases(tmp_path / "c.json"), {("lodash", "2.4.2"): "prod"})
    assert s["reference_size"] == 1  # GHSA and CVE merged; only lodash is confirmed by two databases
    m = s["metrics"]
    assert (m["grype"]["tp"], m["grype"]["fp"], m["trivy"]["fn"]) == (1, 1, 0)
    assert m["guardian"]["precision"] == 1.0 and m["guardian"]["recall"] == 1.0 and m["guardian"]["with_path"] == 1.0


def test_planted_typosquat_is_caught(tmp_path):
    from guardian.agents import discovery, suspicious
    benchmark._base_project(tmp_path)
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        benchmark._git(cmd, tmp_path)
    benchmark._plant("typosquat", tmp_path)
    out = tmp_path / "_o"
    out.mkdir()
    found, _ = suspicious.detect(tmp_path, out, discovery.discover(tmp_path, out), "HEAD")
    assert any(f.kind == "change" and "expresss" in f.title for f in found)


# ---------------- on the real Juice Shop results ----------------
needs_day2 = pytest.mark.skipif(not (REPORTS / "day2" / "remediation_plan.json").exists(), reason="run the Day 2 plan first")


@needs_day2
def test_day2_outputs_are_consistent():
    risks = json.loads((REPORTS / "day2" / "risk_priorities.json").read_text())["items"]
    plan = json.loads((REPORTS / "day2" / "remediation_plan.json").read_text())["actions"]
    vulns = json.loads((REPORTS / "vulnerability_findings.json").read_text())["findings"]
    vuln_pkgs = {f"{f['package']}@{f['installed_version']}" for f in vulns}
    assert {r["subject"] for r in risks if r["kind"] == "vulnerability"} == vuln_pkgs  # every vulnerable package is scored
    for r in risks:
        assert 0 <= r["score"] <= 100 and abs(sum(f["points"] for f in r["factors"]) - r["score"]) < 0.2
    covered = {p for a in plan for p in a["covers_packages"]}
    assert vuln_pkgs <= covered  # every vulnerable package has an action (fix, replace or escalate)
    for a in plan:
        assert a["rollback"] and a["compatibility"].get("level") and a["expected_risk_reduction"].get("statement")
        assert a["auto_applicable"] == bool(a["changes"])
