"""Agent 8 - Validation & Report, part 2: the verified report, the complete story of each finding.

Original finding and evidence -> recommended and approved action -> build and test results ->
before/after risk -> remaining or accepted risk -> final confidence and audit trail.
Writes day2/verified_report.json, .md and .pdf.
"""
import json
from datetime import date, datetime
from pathlib import Path

from guardian.day2 import approvals, reasoning
from guardian.day2.common import audit, day2_dir, now, read_audit, read_json, verify_audit, write_json


def llm_stats(out: Path) -> dict:
    p = day2_dir(out) / "llm_log.jsonl"
    calls, accepted, failed = 0, 0, 0
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            calls += 1
            failed += 1 if e.get("error") else 0
            accepted += len(e.get("accepted", []))
    return {"provider": reasoning.describe_provider(), "calls": calls, "failed_calls": failed, "accepted_answers": accepted}


def final_confidence(val: dict, risks: list, resolved_ids: set, chain_ok: bool) -> tuple[float, str, list]:
    c, why = 0.45, []
    rc = (val or {}).get("combined") or {}
    v = rc.get("verdict", "")
    if v == "Verified":
        c += 0.2
        why.append("the release candidate rebuilt, passed its tests and the rescan found nothing new")
    elif v == "Verified with notes":
        c += 0.12
        why.append("the release candidate passed, with notes: " + "; ".join(rc.get("reasons", [])[:2]))
    elif val:
        why.append("no approved fix passed validation yet")
    else:
        why.append("nothing has been validated yet")
    t = rc.get("tests") or {}
    if t.get("passed"):
        c += 0.1
        why.append(f"{t['passed']} unit tests passed in the sandbox")
    urgent = [r for r in risks if r["tier"] in ("Critical", "High")]
    if urgent:
        share = sum(1 for r in urgent if r["id"] in resolved_ids) / len(urgent)
        c += 0.15 * share
        why.append(f"{sum(1 for r in urgent if r['id'] in resolved_ids)} of {len(urgent)} critical/high risks verified as resolved")
    if chain_ok:
        c += 0.05
        why.append("audit trail hash chain intact")
    if val and (val.get("scanner") == (rc.get("scan") or {}).get("scanner")):
        c += 0.05
        why.append("before and after scanned with the same vulnerability source")
    c = round(min(c, 0.97), 2)
    return c, ("High" if c >= 0.8 else "Medium" if c >= 0.6 else "Low"), why


def build(out: Path, repo_name: str) -> dict:
    out = Path(out)
    d2 = day2_dir(out)
    risks = read_json(d2 / "risk_priorities.json", {"items": []})["items"]
    invs = read_json(d2 / "investigations.json", {"items": []})["items"]
    plan = approvals.load_plan(out)["actions"]
    dec = approvals.current(out)
    val = read_json(d2 / "validation_latest.json")
    chain_ok, chain_msg = verify_audit(out)

    # which actions passed, per action
    case_by_action = {}
    if val:
        for c in val.get("cases", []):
            for aid in c["actions"]:
                case_by_action[aid] = c
        rc = val.get("combined")
        if rc and not val.get("cases"):
            for aid in rc["actions"]:
                case_by_action[aid] = rc
    rc = (val or {}).get("combined") or {}
    rc_actions = set(rc.get("actions", [])) if rc.get("verdict", "").startswith("Verified") else set()
    still = set((rc.get("diff") or {}).get("targeted_still_vulnerable", []))

    action_for_risk = {}
    for a in plan:
        for r in a["covers_risks"]:
            action_for_risk.setdefault(r, a)

    journeys, resolved_ids = [], set()
    for r in risks:
        a = action_for_risk.get(r["id"])
        d = dec.get(a["id"]) if a else None
        case = case_by_action.get(a["id"]) if a else None
        status = "No action planned"
        if a and not d:
            status = "Waiting for a human decision"
        elif d and d["decision"] == "reject":
            status = "Fix rejected by reviewer"
        elif d and d["decision"] == "accept-risk":
            status = f"Risk accepted until {d.get('expires')}"
        elif d and d["decision"] == "escalate":
            status = "Escalated to security review"
        elif d and d["decision"] == "approve":
            if not case:
                status = "Approved, not validated yet"
            elif a["id"] in rc_actions and (r["kind"] != "vulnerability" or r["subject"] not in still):
                status = "Verified remediation"
                resolved_ids.add(r["id"])
            elif case.get("verdict", "").startswith("Verified"):
                status = "Fix validated; not in the release candidate"
            else:
                status = "Fix failed validation: " + "; ".join(case.get("reasons", [])[:1])
        journeys.append({"risk": r["id"], "subject": r["subject"], "kind": r["kind"], "tier": r["tier"], "score": r["score"],
                         "confidence": r["confidence"], "factors": {f["factor"]: f["points"] for f in r["factors"]}, "why": r["reasoning"], "why_source": r["reasoning_source"],
                         "action": a["id"] if a else None, "action_title": a["title"] if a else None,
                         "decision": d, "validation": {"verdict": case.get("verdict"), "reasons": case.get("reasons"),
                                                       "branch": case.get("branch"), "commit": case.get("commit")} if case else None,
                         "status": status})

    remaining = [j for j in journeys if j["status"] != "Verified remediation"]
    accepted = [j for j in journeys if (j["decision"] or {}).get("decision") == "accept-risk"]
    conf, label, why = final_confidence(val, risks, resolved_ids, chain_ok)
    diff = rc.get("diff") or {}
    summary = {
        "risks_total": len(risks), "risks_resolved": len(resolved_ids), "risks_remaining": len(remaining),
        "accepted": len(accepted), "decisions": approvals.summary(out),
        "before": {"grade": diff.get("grade_before"), "advisories": diff.get("advisories_before"), "by_severity": diff.get("severity_before"),
                   "risk_points": round(sum(r["score"] for r in risks), 1)},
        "after": {"grade": diff.get("grade_after"), "advisories": diff.get("advisories_after"), "by_severity": diff.get("severity_after"),
                  "risk_points": round(sum(r["score"] for r in risks if r["id"] not in resolved_ids), 1)},
        "release_candidate": {"verdict": rc.get("verdict"), "reasons": rc.get("reasons"), "branch": rc.get("branch"),
                              "commit": rc.get("commit"), "patch": rc.get("patch"), "actions": rc.get("actions")} if rc else None,
        "final_confidence": conf, "final_confidence_label": label, "final_confidence_reasons": why,
    }
    from guardian.day2 import final_output
    final = final_output.export(out)
    expired = [j for j in accepted if j["decision"].get("expires") and j["decision"]["expires"] < date.today().isoformat()]
    report = {"repo": repo_name, "generated_at": now(), "summary": summary, "journeys": journeys, "final_output": final,
              "investigations": invs, "actions": plan, "decisions": dec, "validation": val,
              "expired_acceptances": [j["risk"] for j in expired],
              "audit": {"ok": chain_ok, "message": chain_msg, "entries": len(read_audit(out))},
              "responsible_ai": {**llm_stats(out), "controls": [
                  "Agents 1-8 find, score and validate with deterministic tools; the LLM only explains evidence they produced.",
                  "Every AI answer is grounding-checked: any advisory id or package@version not in the evidence gets the answer rejected.",
                  "AI text is labelled as inference and shown next to, never mixed with, the verified evidence.",
                  "A named human approves remediation before validation. Verified dashboard imports publish to a dedicated GitHub branch.",
                  "Validation runs in a separate git worktree with dependency install scripts disabled.",
                  "Only package names, versions, advisory text and public registry data are sent to the LLM; no secrets, tokens or source files.",
                  "All prompts and responses are logged in day2/llm_log.jsonl; all decisions in a hash-chained audit log."]}}
    write_json(day2_dir(out) / "verified_report.json", report)
    (day2_dir(out) / "verified_report.md").write_text(to_markdown(report), encoding="utf-8")
    try:
        from guardian.day2.pdf2 import build_pdf2
        build_pdf2(out, report)
    except Exception as err:  # never lose the JSON report because of a PDF problem
        print(f"[day2] PDF not generated: {err}")
    audit(out, "agent:report", "verified-report", {"confidence": conf, "resolved": len(resolved_ids), "remaining": len(remaining)})
    return report


def to_markdown(r: dict) -> str:
    s = r["summary"]
    L = [f"# Verified remediation report: {r['repo']}", "", f"Generated {r['generated_at']}", "",
         "## Outcome", "",
         f"- Risks: {s['risks_total']} prioritised, **{s['risks_resolved']} verified as resolved**, {s['risks_remaining']} remaining ({s['accepted']} accepted)",
         f"- Advisories: {s['before']['advisories']} before → {s['after']['advisories']} after; grade {s['before']['grade']} → {s['after']['grade']}",
         f"- Risk points: {s['before']['risk_points']} → {s['after']['risk_points']}",
         f"- Final confidence: **{s['final_confidence_label']} ({s['final_confidence']})** because " + "; ".join(s["final_confidence_reasons"]),
         ""]
    if s.get("release_candidate"):
        rc = s["release_candidate"]
        L += [f"Release candidate branch `{rc['branch']}` ({(rc.get('commit') or '')[:9]}): **{rc['verdict']}**. " + "; ".join(rc.get("reasons") or []), ""]
    L += ["## Finding by finding", "", "| Risk | Subject | Tier | Action | Decision | Status |", "|---|---|---|---|---|---|"]
    for j in r["journeys"]:
        d = j["decision"]
        L.append(f"| {j['risk']} | {j['subject']} | {j['tier']} ({j['score']}) | {j['action_title'] or '-'} | "
                 f"{(d['decision'] + ' by ' + d['reviewer']) if d else '-'} | {j['status']} |")
    f = r.get("final_output")
    if f:
        L += ["", "## Final output: the committed fix", "",
              f"Branch `{f['branch']}`, commit `{f['commit'][:12]}`. Files changed: "
              + ", ".join(f["files_changed"]) + f". Patches and fixed files: `{f['dir']}/`."]
    L += ["", "## Audit trail", "", f"{r['audit']['message']}.", "", "## Responsible AI", ""]
    L += [f"- {c}" for c in r["responsible_ai"]["controls"]]
    return "\n".join(L) + "\n"
