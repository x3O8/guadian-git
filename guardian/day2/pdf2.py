"""Day 2 PDF: the verified remediation report (built only from day2/*.json)."""
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table

from guardian.day2.common import day2_dir, read_audit
from guardian.pdf_report import (AMBER, BLUE, GREEN, INK, LINE, ORANGE, PAPER, RED, STEEL, S, W, P, PM, head, sev_cell,
                                 t, table)

TIER_COLOR = {"Critical": RED, "High": ORANGE, "Medium": AMBER, "Low": BLUE}
VERDICT_COLOR = {"Verified": GREEN, "Verified with notes": AMBER, "Failed validation": RED, "Not verified": STEEL}


def colored(text, color, bold=True, style="cell"):
    hexv = color.hexval().replace("0x", "#")
    inner = f"<b>{t(text)}</b>" if bold else t(text)
    return Paragraph(f'<font color="{hexv}">{inner}</font>', S[style])


def C(text):
    return P(text, "cell")


def build_pdf2(out: Path, r: dict) -> Path:
    d2 = day2_dir(out)
    path = d2 / "verified_report.pdf"
    s, val = r["summary"], r.get("validation") or {}
    risks = {j["risk"]: j for j in r["journeys"]}
    when = datetime.fromisoformat(r["generated_at"]).strftime("%d %B %Y, %H:%M UTC")

    def footer(canv, doc):
        canv.saveState()
        canv.setStrokeColor(LINE)
        canv.line(15 * mm, 14 * mm, A4[0] - 15 * mm, 14 * mm)
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(STEEL)
        canv.drawString(15 * mm, 9.5 * mm, f"Software Supply Chain Guardian  |  Day 2 verified remediation  |  {r['repo']}")
        canv.drawRightString(A4[0] - 15 * mm, 9.5 * mm, f"Page {doc.page}")
        canv.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm,
                            bottomMargin=20 * mm, title=f"Verified remediation report: {r['repo']}",
                            author="Software Supply Chain Guardian")
    E = [P("Software Supply Chain Guardian  |  Day 2: Brain & Shield", "kicker"), Spacer(1, 4 * mm),
         P(r["repo"], "title"), P("From detection to verified remediation: which risks matter, why, what was changed, "
                                  "who approved it, and what the sandbox rebuild, tests and rescan proved.", "lead"), Spacer(1, 4 * mm)]
    b, a = s["before"], s["after"]
    sev_b, sev_a = b.get("by_severity") or {}, a.get("by_severity") or {}
    rows = [head("", "Before", "After (verified)"),
            [C("Risk grade"), C(b.get("grade") or "-"), C(a.get("grade") or "not validated yet")],
            [C("Known advisories"), C(b.get("advisories") if b.get("advisories") is not None else "-"), C(a.get("advisories") if a.get("advisories") is not None else "-")],
            [C("Critical / high"), C(f"{sev_b.get('critical', 0)} / {sev_b.get('high', 0)}" if sev_b else "-"),
             C(f"{sev_a.get('critical', 0)} / {sev_a.get('high', 0)}" if sev_a else "-")],
            [C("Total risk points (all prioritised risks)"), C(b["risk_points"]), C(a["risk_points"])],
            [C("Risks resolved / remaining / accepted"), C("-"), C(f"{s['risks_resolved']} / {s['risks_remaining']} / {s['accepted']}")]]
    E += [table(rows, [70 * mm, 50 * mm, W - 120 * mm]), Spacer(1, 6 * mm)]
    conf_col = GREEN if s["final_confidence_label"] == "High" else AMBER if s["final_confidence_label"] == "Medium" else RED
    E += [Table([[colored(f"Final confidence: {s['final_confidence_label']} ({s['final_confidence']})", conf_col, style="h2")],
                 [C("Because " + "; ".join(s["final_confidence_reasons"]) + ".")]], colWidths=[W],
                style=[("BOX", (0, 0), (-1, -1), 1.2, conf_col), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5)])]
    if s.get("release_candidate"):
        rc = s["release_candidate"]
        E += [Spacer(1, 5 * mm), P(f"Release candidate: branch {rc['branch']} (commit {(rc.get('commit') or '')[:9]}) - "
                                   f"{rc['verdict']}. {'; '.join(rc.get('reasons') or [])}. It is not merged; a human decides.", "body")]
    E += [Spacer(1, 4 * mm), P(f"Generated {when}. Decisions: {s['decisions']['approve']} approved, {s['decisions']['reject']} rejected, "
                               f"{s['decisions']['accept-risk']} risk accepted, {s['decisions']['escalate']} escalated, "
                               f"{s['decisions']['pending']} pending. Audit trail: {r['audit']['message']}.", "small"), PageBreak()]

    # 1. risk priorities
    E += [P("1. Prioritised risks", "h1"),
          P("Score = severity (max 40) + exploitability (25) + reachability (20) + exposure (15). Exploitability uses CISA KEV "
            "and FIRST EPSS when reachable, otherwise the CVSS vector. Reachability comes from the application's own import "
            "statements. Confidence states how much of this evidence was available rather than assumed.", "body")]
    rows = [head("Risk", "Subject", "Tier", "Score", "Sev", "Expl", "Reach", "Expo", "Conf.")]
    items = sorted(r["journeys"], key=lambda j: -j["score"])
    for j in items[:30]:
        f = j.get("factors", {})
        rows.append([C(j["risk"]), C(j["subject"][:60]), colored(j["tier"], TIER_COLOR.get(j["tier"], STEEL)), C(j["score"]),
                     C(f.get("severity", "")), C(f.get("exploitability", "")), C(f.get("reachability", "")), C(f.get("exposure", "")),
                     C(f"{j['confidence']:.2f}")])
    E += [table(rows, [17 * mm, 62 * mm, 16 * mm, 13 * mm, 12 * mm, 12 * mm, 13 * mm, 12 * mm, W - 157 * mm])]

    E += [CondPageBreak(60 * mm), P("Why the top risks are severe", "h2")]
    for j in items[:8]:
        E += [KeepTogether([PM(f"<b>{t(j['risk'])} {t(j['subject'])}</b> - {t(j['tier'])} ({j['score']})", "body"),
                            P(j["why"], "body"), P(f"Reasoning source: {j['why_source']}", "small"), Spacer(1, 2 * mm)])]

    # 2. investigations
    E += [PageBreak(), P("2. Suspicious changes and non-CVE risks", "h1"),
          P("Verified evidence (read from files, git or the npm registry) is shown separately from inference "
            "(an interpretation, labelled with its source). Scripts were read as text, never run.", "body")]
    for inv in r["investigations"]:
        col = RED if inv["verdict"] == "Suspicious" else AMBER if inv["verdict"] == "Needs review" else GREEN
        ev = [[P("Verified evidence", "cellhead"), P("Source", "cellhead")]] + [[C(e["fact"][:400]), C(e["source"][:80])] for e in inv["verified_evidence"][:8]]
        block = [PM(f'<font color="{col.hexval().replace("0x", "#")}"><b>{t(inv["verdict"])}</b></font>  '
                    f'<b>{t(inv["id"])} {t(inv["title"])}</b>', "body"),
                 table(ev, [W * 0.72, W * 0.28]), Spacer(1, 1.5 * mm),
                 PM(f"<b>Inference</b> ({t(inv['inference_source'])}): {t(inv['inference'])}", "small"),
                 PM(f"<b>Remedy:</b> {t(inv['remedy'])}", "small"), Spacer(1, 4 * mm)]
        E += [KeepTogether(block)]

    # 3. plan and decisions
    E += [PageBreak(), P("3. Recommended remediation and human decisions", "h1"),
          P("Every action lists its exact change, expected risk reduction, compatibility impact and rollback. Only actions "
            "a named reviewer approved were applied, and only in the sandbox.", "body")]
    dec = r["decisions"]
    for act in r["actions"]:
        d = dec.get(act["id"])
        dtxt = (f"{d['decision']} by {d['reviewer']} on {d['at'][:16].replace('T', ' ')}" + (f" - \"{d['comment']}\"" if d.get("comment") else "")
                + (f" (review by {d['expires']})" if d.get("expires") else "")) if d else "pending"
        ch = "; ".join(f"{c['file']}: {c['op']} {c['target']}" + (f" = {c['value']}" if c.get("value") else "") for c in act["changes"]) or "no automatic change"
        rows = [[C("Change"), C(ch)], [C("Covers"), C(", ".join(act["covers_packages"]) or ", ".join(act["covers_risks"]))],
                [C("Expected risk reduction"), C(act["expected_risk_reduction"].get("statement", ""))],
                [C("Compatibility"), C(f"{act['compatibility'].get('level')}: {act['compatibility'].get('summary', '')} {act['compatibility'].get('check', '')}")],
                [C("Rollback"), C(act["rollback"])]] + ([[C("Rationale"), C(f"{act['rationale']} [{act['rationale_source']}]")]] if act["rationale"] else []) + [
                [C("Human decision"), colored(dtxt, GREEN if d and d["decision"] == "approve" else AMBER if d else STEEL, bold=bool(d))]]
        E += [KeepTogether([PM(f"<b>{t(act['id'])} {t(act['title'])}</b>  ({t(act['type'])}, priority {t(act['priority'])}, "
                               f"confidence {act['confidence']})", "body"),
                            table(rows, [34 * mm, W - 34 * mm], head=False), Spacer(1, 4 * mm)])]

    # 4. validation
    E += [PageBreak(), P("4. Validation: build, test, rescan", "h1")]
    if not val:
        E += [P("No validation has been run yet.", "body")]
    else:
        E += [P(f"Sandbox run {val['run']} from base commit {val['base_commit'][:9]}, scanner {val['scanner']}. "
                f"Install: {val['profile'].get('install')}; build: {val['profile'].get('build') or 'none found'}; "
                f"tests: {val['profile'].get('test') or 'none found'}.", "body")]
        cases = [val["baseline"]] + val.get("cases", []) + ([val["combined"]] if val.get("combined") else [])
        for c in cases:
            rows = [head("Step", "Result", "Seconds", "Detail")]
            for st in c["steps"]:
                rows.append([C(st["step"]), colored(st["status"], GREEN if st["status"] == "pass" else RED if st["status"] == "fail" else STEEL),
                             C(st["seconds"]), C(st["detail"][:220])])
            v = c.get("verdict")
            title = f"{c['name']}" + (f" - {v}" if v else " (no changes: the reference run)")
            block = [PM(f"<b>{t(title)}</b>" + (f"  <font color='#5E6E7E'>{t('; '.join(c.get('reasons') or []))}</font>" if v else ""), "body"),
                     table(rows, [44 * mm, 15 * mm, 15 * mm, W - 74 * mm])]
            dd = c.get("diff") or {}
            if dd:
                block += [Spacer(1, 1.5 * mm), table([
                    head("Before and after", "Before", "After"),
                    [C("Advisories"), C(dd["advisories_before"]), C(dd["advisories_after"])],
                    [C("SBOM components (CycloneDX)"), C(dd["sbom_components_before"]), C(dd["sbom_components_after"])],
                    [C("Installed packages"), C(dd["packages_before"]), C(dd["packages_after"])],
                    [C("Resolved / newly introduced advisories"), C(len(dd["resolved"])), C(len(dd["new_vulnerabilities"]))],
                    [C("Packages added / removed / new names"), C(f"{len(dd['added'])} / {len(dd['removed'])}"), C(len(dd["new_dependencies"]))]],
                    [70 * mm, 30 * mm, W - 100 * mm])]
                if dd["new_vulnerabilities"]:
                    block += [P("Newly introduced: " + ", ".join(f"{x['id']} in {x['package']} ({x['severity']})" for x in dd["new_vulnerabilities"][:8]), "small")]
                if dd["new_dependencies"]:
                    block += [P("New dependency names: " + ", ".join(dd["new_dependencies"][:25]), "small")]
            if c.get("branch") and c.get("commit"):
                block += [P(f"Branch {c['branch']}, commit {c['commit'][:9]}. Rollback: git revert {c['commit'][:9]}.", "small")]
            E += [CondPageBreak(50 * mm)] + block + [Spacer(1, 5 * mm)]

    fo = r.get("final_output")
    if fo:
        E += [CondPageBreak(60 * mm), P("Final output: the validated fix, committed", "h2"),
              table([[C("Branch"), C(fo["branch"])],
                     [C("Commit"), P(fo["commit"], "cellmono")],
                     [C("Fixes included"), C(", ".join(fo["actions"]))],
                     [C("Files changed"), C(", ".join(fo["files_changed"]) or "see patch")],
                     [C("Exported to"), C(fo["dir"] + "/ : release-candidate.patch, 0001-Guardian-remediation.patch (git am), "
                                          "fixed package.json and package-lock.json, FINAL.md")],
                     [C("To apply"), C(f"a person reviews, then: git merge --no-ff {fo['branch']}  (undo: git revert -m 1 HEAD)")]],
                    [34 * mm, W - 34 * mm], head=False)]

    # 5. remaining risk
    E += [PageBreak(), P("5. Remaining and accepted risk", "h1")]
    rows = [head("Risk", "Subject", "Tier", "Status")]
    for j in r["journeys"]:
        if j["status"] != "Verified remediation":
            rows.append([C(j["risk"]), C(j["subject"][:70]), colored(j["tier"], TIER_COLOR.get(j["tier"], STEEL)), C(j["status"])])
    E += [table(rows, [17 * mm, 80 * mm, 18 * mm, W - 115 * mm])] if len(rows) > 1 else [P("None: every prioritised risk was verified as resolved.", "body")]
    if r.get("expired_acceptances"):
        E += [P("Risk acceptances past their review date: " + ", ".join(r["expired_acceptances"]), "body")]

    # 6. audit
    E += [PageBreak(), P("6. Audit trail", "h1"),
          P(f"{r['audit']['message']}. Each entry stores the SHA-256 of the previous one, so editing or deleting history "
            "breaks the chain and is detected.", "body")]
    rows = [head("#", "Time (UTC)", "Actor", "Event", "Details", "Hash")]
    for e in read_audit(out)[-80:]:
        det = ", ".join(f"{k}: {v}" for k, v in e["details"].items() if k in ("action", "decision", "verdict", "comment", "run", "title"))
        rows.append([C(e["seq"]), C(e["at"][5:16].replace("T", " ")), C(e["actor"]), C(e["event"]), C(det[:160]), P(e["hash"][:12], "cellmono")])
    E += [table(rows, [8 * mm, 22 * mm, 30 * mm, 28 * mm, W - 110 * mm, 22 * mm])]

    # 7. responsible AI
    ra = r["responsible_ai"]
    E += [PageBreak(), P("7. Responsible AI and security note", "h1"),
          P(f"Reasoning model: {ra['provider']}. LLM calls: {ra['calls']} ({ra['failed_calls']} failed); answers accepted after the "
            f"grounding check: {ra['accepted_answers']}. Where no LLM is configured, explanations are rule-based and labelled so.", "body")]
    E += [P("- " + c, "body") for c in ra["controls"]]
    doc.build(E, onFirstPage=footer, onLaterPages=footer)
    return path
