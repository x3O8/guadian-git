"""Day 2 dashboard pages: risk priorities, investigation, approval desk, validation, verified report,
the detection-to-fix journey, and the tool benchmark. Imported by app.py."""
import io
import json
import subprocess
import zipfile
from datetime import date, timedelta
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from guardian.day2 import approvals, reasoning
from guardian.day2.common import day2_dir, read_audit, read_json, verify_audit

BG, SURFACE, LINE, TEXT, MUTED = "#0E1A26", "#16263A", "#2B3D52", "#E6EDF3", "#9FB0C2"
BLUE, RED, ORANGE, AMBER, GREEN, VIOLET = "#5B9BE6", "#F0645A", "#F08A4B", "#E3B341", "#4CC38A", "#B39DFF"
TIER = {"Critical": RED, "High": ORANGE, "Medium": AMBER, "Low": BLUE}
VERDICT = {"Suspicious": RED, "Needs review": AMBER, "Expected": GREEN,
           "Verified": GREEN, "Verified with notes": AMBER, "Failed validation": RED, "Not verified": MUTED}
DECISION = {"approve": (GREEN, "Approved"), "reject": (RED, "Rejected"), "accept-risk": (AMBER, "Risk accepted"),
            "escalate": (VIOLET, "Escalated")}
FACTOR_COLORS = {"severity": "#F0645A", "exploitability": "#F08A4B", "reachability": "#5B9BE6", "exposure": "#B39DFF"}

CSS = f"""<style>
.belt {{ display:grid; grid-template-columns: repeat(6, 1fr); gap:0; margin:.4rem 0 1.4rem; }}
.belt .st {{ position:relative; padding:.8rem .9rem .9rem 1.1rem; border-top:3px solid var(--c); background:{SURFACE};
            margin-right:6px; clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 50%, calc(100% - 12px) 100%, 0 100%, 12px 50%); }}
.belt .st:first-child {{ clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 50%, calc(100% - 12px) 100%, 0 100%); }}
.belt .n {{ font-size:1.9rem; font-weight:800; font-stretch:72%; line-height:1; color:var(--c); }}
.belt .l {{ font-weight:700; font-stretch:85%; color:{TEXT}; margin-top:.2rem; font-size:.95rem; }}
.belt .s {{ color:{MUTED}; font-size:.78rem; line-height:1.3; margin-top:.15rem; }}
.chip {{ display:inline-block; border:1px solid var(--c); color:var(--c); border-radius:999px; padding:.05rem .55rem;
        font-size:.76rem; font-weight:700; margin-right:.3rem; white-space:nowrap; }}
.fact {{ border-left:3px solid {GREEN}; padding:.35rem .7rem; margin:.25rem 0; background:#132232; font-size:.9rem; line-height:1.45; }}
.fact .src {{ color:{MUTED}; font-size:.76rem; display:block; margin-top:.1rem; }}
.infer {{ border:1px dashed {VIOLET}; border-radius:6px; padding:.6rem .8rem; background:#1A1D33; font-size:.93rem; line-height:1.5; }}
.infer .who {{ color:{VIOLET}; font-size:.76rem; font-weight:700; margin-bottom:.25rem; }}
.verdict {{ display:inline-block; font-weight:800; font-stretch:75%; font-size:1.05rem; color:var(--c); border:2px solid var(--c);
           border-radius:5px; padding:.05rem .55rem; transform:rotate(-2deg); margin-right:.5rem; }}
.bar4 {{ display:flex; height:12px; border-radius:2px; overflow:hidden; background:#22344A; margin:.2rem 0 .1rem; }}
.bar4 span {{ display:block; height:100%; }}
.journey {{ border-left:2px solid {LINE}; margin-left:.6rem; padding-left:1.4rem; }}
.journey .stop {{ position:relative; padding:.2rem 0 1.1rem; }}
.journey .stop:before {{ content:''; position:absolute; left:-1.95rem; top:.35rem; width:.9rem; height:.9rem; border-radius:50%;
                        background:var(--c); box-shadow:0 0 0 4px {BG}; }}
.journey .t {{ font-weight:800; font-stretch:82%; font-size:1.05rem; color:{TEXT}; }}
.journey .d {{ color:{TEXT}; font-size:.93rem; line-height:1.5; margin-top:.15rem; }}
.journey .m {{ color:{MUTED}; font-size:.8rem; }}
.big2 {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap:.6rem; margin:.4rem 0 1rem; }}
.big2 > div {{ background:{SURFACE}; border:1px solid {LINE}; border-radius:6px; padding:.7rem .9rem; }}
.big2 .k {{ color:{MUTED}; font-size:.8rem; }}
.big2 .v {{ font-size:1.5rem; font-weight:800; font-stretch:80%; color:{TEXT}; }}
.big2 .v s {{ color:{MUTED}; font-weight:600; font-size:1.05rem; margin-right:.35rem; }}
.stepchips span {{ display:inline-block; font-size:.75rem; font-weight:700; padding:.05rem .45rem; border-radius:3px; margin:0 .2rem .2rem 0; color:{BG}; }}
</style>"""


# ---------------- helpers ----------------
def chip(text, color):
    return f'<span class="chip" style="--c:{color}">{escape(str(text))}</span>'


def lead(text):
    st.markdown(f'<p class="lead">{text}</p>', unsafe_allow_html=True)


def factor_bar(factors: list) -> str:
    return '<div class="bar4">' + "".join(
        f'<span title="{escape(f["factor"])}: {f["points"]} of {f["max_points"]}" '
        f'style="width:{f["points"]}%;background:{FACTOR_COLORS[f["factor"]]}"></span>' for f in factors) + "</div>"


def source_label(src: str) -> str:
    if src.startswith("AI"):
        return chip("AI inference · grounded", VIOLET)
    return chip("rule-based", MUTED)


def load_d2(out: Path) -> dict:
    d2 = day2_dir(out)
    return {"risks": read_json(d2 / "risk_priorities.json"), "invs": read_json(d2 / "investigations.json"),
            "plan": read_json(d2 / "remediation_plan.json"), "val": read_json(d2 / "validation_latest.json"),
            "report": read_json(d2 / "verified_report.json"), "decisions": approvals.current(out) if (d2 / "remediation_plan.json").exists() else {}}


def run_workflow(repo: Path, out: Path, phase: str, label: str, **kw):
    from guardian.day2.workflow2 import stream
    with st.status(label, expanded=True) as status:
        final = None
        lines = []

        def log(msg):
            lines.append(msg)
            status.write(f"`{msg}`")
        for kind, item in stream(str(repo), str(out), phase, log=log, **kw):
            if kind == "log":
                status.write(f"**{item.agent}**: {dict(ok='done', error='failed').get(item.status, item.status)}. {item.message}")
            else:
                final = item
        if final and final.get("errors"):
            status.update(label="Finished with errors", state="error", expanded=True)
            for e in final["errors"]:
                st.error(e)
        else:
            status.update(label=label.replace("Running", "Finished").replace("…", ""), state="complete", expanded=False)
    st.cache_data.clear()
    return final


def need_plan(d: dict, repo: Path, out: Path) -> bool:
    if d["plan"] and d["risks"]:
        return True
    st.markdown("### Day 2 hasn't run for this repository yet")
    st.markdown("Agents 6 and 7 read the Day 1 evidence, score each risk, investigate non-CVE changes and propose fixes. "
                "Nothing is changed: the plan waits for your decision.")
    if st.button("Run Day 2 analysis (agents 6–7)", type="primary", key="plan_empty"):
        run_workflow(repo, out, "plan", "Running agents 6–7…")
        st.rerun()
    return False


def llm_box():
    p = reasoning.describe_provider()
    on = not p.startswith("rule-based")
    st.markdown(chip(("Reasoning: " + p) if on else "Reasoning: rule-based (no LLM key set)", VIOLET if on else MUTED),
                unsafe_allow_html=True)
    if not on:
        with st.expander("Turn on LLM reasoning"):
            st.markdown("For Groq's `openai/gpt-oss-20b`, set your Groq key in CMD and start the dashboard from that window.")
            st.code('set "GROQ_API_KEY=your_groq_key"', language="bat")
            st.caption("Then run Day 2 analysis. For Anthropic or a custom OpenAI-compatible endpoint, see the README.")
            st.caption("The LLM only explains evidence the agents verified. Any answer naming an advisory or version that is not in "
                       "the evidence is rejected and the rule-based explanation is kept.")


def git_panel(repo: Path, out: Path):
    """What is now in the target repo's git: Guardian branches, approval tags, and the commit with its approver."""
    from guardian.day2.final_output import git_view
    gv = git_view(repo)
    st.markdown("### In git: branches, commits and approvals")
    if not gv["branches"]:
        st.markdown("No Guardian branches yet: they appear after validation.")
        return
    st.markdown(f"These live in `target/{repo.name}`'s own git. "
                "Each commit's subject names who approved it; the approval tag is created in the approver's name.")
    st.dataframe(pd.DataFrame(gv["branches"]), hide_index=True, width="stretch",
                 column_config={"subject": st.column_config.TextColumn("commit message (who approved what)", width="large")})
    if gv["tags"]:
        st.dataframe(pd.DataFrame(gv["tags"]), hide_index=True, width="stretch",
                     column_config={"tagger": st.column_config.TextColumn("approved by (tagger)")})
    fo = read_json(day2_dir(out) / "final_output.json") or {}
    if fo.get("commit_log"):
        st.markdown(f"**Validated commit on `{fo['branch']}`** (`git log -1 {fo['branch']}`):")
        st.code(fo["commit_log"][:3000], language="text")
    st.code(f"git -C target\\{repo.name} branch --list \"guardian/*\" -v\n"
            f"git -C target\\{repo.name} tag -n9 --list \"guardian-approved/*\"\n"
            f"git -C target\\{repo.name} log -1 {fo.get('branch', '<branch>')}", language="bat")


# ================= pages =================
def mission(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## Day 2 · From finding to verified fix")
    lead("Three agents and one human gate: agent 6 decides which risks matter, agent 7 proposes a safe fix for each, a person approves, then agent 8 proves "
         "the fix in a sandbox: rebuild, run the tests, rescan. Nothing reaches your code without a named approval.")
    d = load_d2(out)
    llm_box()
    analysis_col, report_col = st.columns(2)
    if analysis_col.button("Run Day 2 analysis (agents 6–7)", type="primary" if not d["plan"] else "secondary", width="stretch"):
        run_workflow(repo, out, "plan", "Running agents 6–7…")
        st.rerun()
    approved = approvals.approved_actions(out) if d["plan"] else []
    if report_col.button("Rebuild the verified report", width="stretch", disabled=not d["plan"]):
        from guardian.day2 import verify_report
        verify_report.build(out, repo.name)
        st.rerun()
    if not d["plan"]:
        st.info("Start with **Run Day 2 analysis**. It uses the Day 1 results already on screen.")
        return
    risks, plan, dec, val = d["risks"]["items"], d["plan"]["actions"], d["decisions"], d["val"]
    urgent = sum(1 for r in risks if r["tier"] in ("Critical", "High"))
    auto = sum(a_["auto_applicable"] for a_ in plan)
    s = approvals.summary(out)
    rc = (val or {}).get("combined") or {}
    rep = d["report"] or {}
    resolved = (rep.get("summary") or {}).get("risks_resolved")
    stations = [
        ("Prioritised risk", len(risks), f"{urgent} critical or high", RED if urgent else GREEN),
        ("Recommended fix", len(plan), f"{auto} testable automatically", BLUE),
        ("Human approval", s["approve"], f"{s['pending']} waiting, {s['reject']} rejected, {s['accept-risk']} accepted", AMBER if s["pending"] else GREEN),
        ("Build & test", len((val or {}).get("passed", [])) if val else "–",
         f"of {len((val or {}).get('approved', []))} approved passed" if val else "not run yet", GREEN if val else MUTED),
        ("Rescan", (rc.get("diff") or {}).get("advisories_after", "–"),
         f"advisories, was {(rc.get('diff') or {}).get('advisories_before')}" if rc.get("diff") else "not run yet", GREEN if rc else MUTED),
        ("Verified remediation", resolved if resolved is not None else "–",
         f"risks resolved, {rep['summary']['final_confidence_label'].lower()} confidence" if rep.get("summary") else "report not built", GREEN if resolved else MUTED),
    ]
    st.markdown('<div class="belt">' + "".join(
        f'<div class="st" style="--c:{c_}"><div class="n">{escape(str(n))}</div><div class="l">{escape(l)}</div>'
        f'<div class="s">{escape(sub)}</div></div>' for l, n, sub, c_ in stations) + "</div>", unsafe_allow_html=True)

    st.markdown("### What needs you now")
    todo = [x for x in plan if x["id"] not in dec]
    if todo:
        st.markdown(f"**{len(todo)} action{'s' if len(todo) != 1 else ''} waiting for a decision** on **7 · Remediation & approval**. "
                    f"The most urgent: " + ", ".join(f"`{x['id']}` {escape(x['title'])}" for x in todo[:3]) + ".")
    elif approved and not val:
        st.markdown("Every action has a decision. Open **8 · Validation** to test the approved fixes in the sandbox.")
    else:
        st.markdown("Nothing is waiting. Open **8 · Verified report** for the full story.")
    if rc:
        st.markdown(f"Release candidate `{rc.get('branch')}`: " + chip(rc.get("verdict", "?"), VERDICT.get(rc.get("verdict"), MUTED))
                    + escape("; ".join(rc.get("reasons") or [])), unsafe_allow_html=True)
    st.markdown("### Day 2 agents, last runs")
    rows = [{"time (UTC)": e["at"][:19].replace("T", " "), "who": e["actor"], "event": e["event"],
             "details": e["details"].get("message") or ", ".join(f"{k}: {v}" for k, v in e["details"].items() if k in ("action", "decision", "verdict", "comment"))}
            for e in read_audit(out) if e["event"] in ("agent-finished", "agent-failed", "decision", "release-candidate", "verified-report")][-12:][::-1]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def risks_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## 6 · Risk analysis: priorities")
    lead("Every vulnerable package and every non-CVE supply-chain risk on one 0–100 scale: <b>severity</b> (40) + "
         "<b>exploitability</b> (25) + <b>reachability</b> (20) + <b>exposure</b> (15). Each point has a reason you can check, "
         "and a confidence that says how much of the evidence was real rather than assumed.")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    items = d["risks"]["items"]
    for n in d["risks"].get("exploitability_notes", []):
        st.caption(n)
    c = st.columns(5)
    for col, t in zip(c, ["Critical", "High", "Medium", "Low"]):
        col.metric(f"{t} risk", sum(1 for i in items if i["tier"] == t))
    c[4].metric("High confidence", sum(1 for i in items if i["confidence_label"] == "High"))
    st.markdown(" ".join(f'<span class="swatch" style="background:{v}"></span>{k}' for k, v in FACTOR_COLORS.items()),
                unsafe_allow_html=True)
    rows = [{"risk": f"{i['id']} {i['subject'][:48]}", "factor": f["factor"], "points": f["points"], "reason": f["reason"]}
            for i in items[:20] for f in i["factors"]]
    order = [f"{i['id']} {i['subject'][:48]}" for i in items[:20]]
    chart = alt.Chart(pd.DataFrame(rows)).mark_bar().encode(
        x=alt.X("sum(points):Q", title="risk score (0–100)", scale=alt.Scale(domain=[0, 100])),
        y=alt.Y("risk:N", sort=order, title=None, axis=alt.Axis(labelLimit=360)),
        color=alt.Color("factor:N", scale=alt.Scale(domain=list(FACTOR_COLORS), range=list(FACTOR_COLORS.values())), legend=None),
        order=alt.Order("factor_order:Q"), tooltip=["risk", "factor", "points", "reason"]
    ).transform_calculate(factor_order="indexof(['severity','exploitability','reachability','exposure'], datum.factor)").properties(height=alt.Step(22))
    st.altair_chart(chart, width="stretch")
    with st.expander("How each factor is scored"):
        for k, v in d["risks"]["method"].items():
            st.markdown(f"**{k.title()}**: {v}")

    a, b = st.columns(2)
    tiers = a.multiselect("Tier", list(TIER), list(TIER))
    kinds = b.multiselect("Kind", ["vulnerability", "supply-chain"], ["vulnerability", "supply-chain"],
                          format_func={"vulnerability": "Known vulnerability (CVE/GHSA)", "supply-chain": "Supply-chain risk (no CVE)"}.get)
    action_for = {}
    for x in d["plan"]["actions"]:
        for r in x["covers_risks"]:
            action_for.setdefault(r, x)
    for i in items:
        if i["tier"] not in tiers or i["kind"] not in kinds:
            continue
        with st.expander(f"{i['id']}  ·  {i['subject'][:80]}  ·  {i['tier']} {i['score']}  ·  confidence {i['confidence_label']}"):
            st.markdown(factor_bar(i["factors"]), unsafe_allow_html=True)
            l, r = st.columns([1.15, 1], gap="large")
            with l:
                st.markdown("**Why it is severe** " + source_label(i["reasoning_source"]), unsafe_allow_html=True)
                st.markdown(f'<div class="infer"><div class="who">{escape(i["reasoning_source"])}</div>{escape(i["reasoning"])}</div>',
                            unsafe_allow_html=True)
                st.markdown("**Score, factor by factor**")
                st.dataframe(pd.DataFrame([{"factor": f["factor"], "points": f"{f['points']} / {f['max_points']:.0f}", "because": f["reason"]}
                                           for f in i["factors"]]), hide_index=True, width="stretch")
                st.markdown(f"**Confidence {i['confidence_label']} ({i['confidence']})**: " + "; ".join(i["confidence_reasons"]) + ".")
            with r:
                st.markdown("**Verified evidence**")
                ev = i["evidence"]
                if i["kind"] == "vulnerability":
                    rch = ev["reachability"]
                    facts = [(f"Installed {ev['package']} ({'listed in package.json' if ev['direct'] else 'pulled in by ' + ', '.join(ev['introduced_via'][:3])}), used in {ev['scope']}", "lockfile + dependency graph"),
                             ("Path: " + " → ".join(ev["dependency_path"]), "dependency graph (Agent 3)"),
                             (f"Reachability: {rch['label']}" + (f" — {', '.join(rch['files'][:4])}" if rch["files"] else ""), "source-code imports")]
                    for adv in ev["advisories"][:6]:
                        facts.append((f"{adv['id']} ({adv['severity']}, CVSS {adv['cvss'] or 'n/a'}): {adv['title'][:120]}"
                                      + (f" — fixed in {adv['fixed_version']}" if adv.get("fixed_version") else " — no fix"), "advisory database (Agent 4)"))
                    for cw in ev.get("cwe_meaning", [])[:3]:
                        facts.append((f"{cw['cwe']} {cw['name']}: {cw['impact']}", "MITRE CWE"))
                else:
                    facts = [(f["fact"], f["source"]) for f in ev.get("facts", [])[:8]]
                st.markdown("".join(f'<div class="fact">{escape(t)}<span class="src">{escape(s)}</span></div>' for t, s in facts),
                            unsafe_allow_html=True)
                act = action_for.get(i["id"])
                if act:
                    dd = d["decisions"].get(act["id"])
                    st.markdown(f"**Proposed fix:** `{act['id']}` {escape(act['title'])}  " +
                                (chip(DECISION[dd["decision"]][1], DECISION[dd["decision"]][0]) if dd else chip("waiting for a decision", MUTED)),
                                unsafe_allow_html=True)


def investigate_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## 6 · Risk analysis: suspicious changes")
    lead("Risks that have no CVE: install scripts, where packages are downloaded from, whether lockfile hashes match the registry, "
         "build provenance, deprecated packages, loose version ranges, container images, CI actions, and what changed since the "
         "baseline. <b>Verified evidence</b> (green) is kept apart from <b>inference</b> (violet, dashed).")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    items = d["invs"]["items"]
    st.caption(d["invs"].get("registry", ""))
    c = st.columns(3)
    for col, v in zip(c, ["Suspicious", "Needs review", "Expected"]):
        col.metric(v, sum(1 for i in items if i["verdict"] == v))
    show = st.radio("Show", ["Needs attention", "Everything"], horizontal=True)
    for i in items:
        if show == "Needs attention" and i["verdict"] == "Expected":
            continue
        with st.container(border=True):
            st.markdown(f'<span class="verdict" style="--c:{VERDICT[i["verdict"]]}">{escape(i["verdict"])}</span>'
                        f'<b>{escape(i["id"])} · {escape(i["title"])}</b> {chip(i["severity"], MUTED)}'
                        + (chip("Day 1 " + i["day1_ref"][:30], BLUE) if i.get("day1_ref") else ""), unsafe_allow_html=True)
            l, r = st.columns([1.2, 1], gap="large")
            with l:
                st.markdown("**Verified evidence**")
                st.markdown("".join(f'<div class="fact">{escape(e["fact"])}<span class="src">{escape(e["source"])}</span></div>'
                                    for e in i["verified_evidence"]), unsafe_allow_html=True)
            with r:
                st.markdown("**Inference** " + source_label(i["inference_source"]), unsafe_allow_html=True)
                st.markdown(f'<div class="infer"><div class="who">{escape(i["inference_source"])} — an interpretation, not evidence</div>'
                            f'{escape(i["inference"])}</div>', unsafe_allow_html=True)
                st.markdown(f"**Remedy:** {escape(i['remedy'])}")
    st.caption("To look for changes over a longer period, pick an older commit under Inspection settings in the sidebar, "
               "choose Inspect again, then run the Day 2 analysis again.")


def approval_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## 7 · Remediation & human approval")
    lead("Each fix is a change request: the exact edit, what it should remove, what could break and how to undo it. "
         "<b>Nothing is applied until a named reviewer approves it</b>, and even then only in a sandbox copy. "
         "Reject, accept the risk with a review date, or send it to security review instead.")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    plan, dec = d["plan"]["actions"], d["decisions"]
    s = approvals.summary(out)
    reviewer = st.text_input("Reviewer (your name is recorded with every decision)", key="reviewer",
                             value=st.session_state.get("reviewer", ""), placeholder="e.g. Rohit Praveen Nair")
    c = st.columns(5)
    for col, (k, lab) in zip(c, [("pending", "Waiting"), ("approve", "Approved"), ("reject", "Rejected"),
                                 ("accept-risk", "Risk accepted"), ("escalate", "Escalated")]):
        col.metric(lab, s[k])
    appr = [x for x in plan if dec.get(x["id"], {}).get("decision") == "approve"]
    if appr:
        cleared = sum(x["advisories_cleared"] for x in appr)
        st.markdown(f"If every approved fix works: about **{cleared} advisories** cleared and **"
                    f"{sum(x['expected_risk_reduction'].get('risk_points_removed', 0) for x in appr):.0f} risk points** removed. "
                    "The sandbox on **8 · Validation** measures the real effect.")
    view = st.radio("Show", ["Waiting for a decision", "All actions"], horizontal=True)
    for x in plan:
        cur = dec.get(x["id"])
        if view.startswith("Waiting") and cur:
            continue
        with st.container(border=True):
            head = (f"{chip(x['priority'], TIER.get(x['priority'], MUTED))}{chip(x['type'], BLUE)}"
                    f"{chip('confidence ' + str(x['confidence']), MUTED)}"
                    + (chip(DECISION[cur['decision']][1] + ' · ' + cur['reviewer'], DECISION[cur['decision']][0]) if cur else chip('waiting', MUTED)))
            st.markdown(f"#### {escape(x['id'])} · {escape(x['title'])}")
            st.markdown(head, unsafe_allow_html=True)
            l, r = st.columns([1.3, 1], gap="large")
            with l:
                if x["changes"]:
                    st.markdown("**The change**")
                    st.code("\n".join(f"{ch['file']}: " + {"set-dependency": f'"{ch["target"]}": "{ch["value"]}"  ({ch.get("section")})',
                                                          "add-override": f'overrides."{ch["target"]}": "{ch["value"]}"',
                                                          "set-json": f'{ch["target"]} = {ch["value"]}',
                                                          "replace-text": f'{ch["target"]}  →  {ch["value"]}',
                                                          "restore-file": f"restore from {ch['value']}"}.get(ch["op"], ch["op"])
                                      for ch in x["changes"]), language="text")
                else:
                    st.markdown("**No automatic change.** " + escape(x["rationale"] or x["compatibility"].get("check", "")))
                if x["covers_packages"]:
                    st.markdown("**Removes** " + ", ".join(f"`{p}`" for p in x["covers_packages"]) + f" — risks {', '.join(x['covers_risks'])}")
                st.markdown(f"**Expected risk reduction:** {escape(x['expected_risk_reduction'].get('statement', ''))}")
                comp = x["compatibility"]
                st.markdown(f"**Compatibility impact:** {chip(comp.get('level', '?'), {'High': RED, 'Medium': AMBER, 'Low': GREEN}.get(comp.get('level'), MUTED))}"
                            f"{escape(comp.get('summary', ''))} {escape(comp.get('check', ''))}", unsafe_allow_html=True)
                st.markdown(f"**Rollback:** {escape(x['rollback'])}")
                if x["rationale"] and x["changes"]:
                    st.markdown(f'<div class="infer"><div class="who">Rationale · {escape(x["rationale_source"])}</div>{escape(x["rationale"])}</div>',
                                unsafe_allow_html=True)
            with r:
                if cur:
                    st.markdown(f"**Decision:** {DECISION[cur['decision']][1]} by **{escape(cur['reviewer'])}** on "
                                f"{cur['at'][:16].replace('T', ' ')} UTC" + (f"  \n“{escape(cur['comment'])}”" if cur.get("comment") else "")
                                + (f"  \nReview by {cur['expires']}" if cur.get("expires") else ""))
                    if st.button("Withdraw decision", key=f"wd_{x['id']}"):
                        approvals.clear(out, x["id"], reviewer)
                        st.rerun()
                else:
                    with st.form(f"f_{x['id']}"):
                        opts = (["approve"] if x["auto_applicable"] else []) + ["reject", "accept-risk", "escalate"]
                        choice = st.radio("Decision", opts, format_func=lambda k: approvals.CHOICES[k], key=f"r_{x['id']}")
                        comment = st.text_area("Reason (required unless approving)", key=f"c_{x['id']}", height=70)
                        until = st.date_input("Review the accepted risk by", value=date.today() + timedelta(days=30), key=f"d_{x['id']}")
                        if st.form_submit_button("Record decision", type="primary"):
                            try:
                                approvals.decide(out, x["id"], choice, reviewer, comment, str(until) if choice == "accept-risk" else None)
                                st.rerun()
                            except ValueError as err:
                                st.error(str(err))


def validation_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## 8 · Validate the proposed fix")
    lead("Test before you trust. Each approved fix is applied on its own branch in a sandbox copy, the dependency tree is "
         "re-resolved with install scripts off, then the app is <b>built</b>, its <b>unit tests run</b>, every changed package "
         "is loaded once, and the result is <b>rescanned</b> by the Day 1 agents. Everything is compared with an untouched "
         "baseline run, so only differences caused by the fix count.")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    approved = approvals.approved_actions(out)
    from guardian.day2.validate import profile
    prof = profile(repo)
    with st.container(border=True):
        st.markdown(f"**Approved and ready:** " + (", ".join(f"`{a['id']}` {escape(a['title'])}" for a in approved) or "none yet — approve on page 7"))
        def cmd(c):
            return ("npm " if c and "npm" in Path(str(c[0])).name.lower() else Path(str(c[0])).stem + " ") + " ".join(map(str, c[1:])) if c else "none found"
        st.markdown(f"Install `{cmd(prof['install'])}` · build `{cmd(prof['build'])}` · tests `{cmd(prof['test'])}`")
        a, b, c = st.columns([1.2, 1, 1.4])
        mode = a.radio("Mode", ["each", "together"], horizontal=True,
                       format_func={"each": "Each fix alone, then together", "together": "All together (faster)"}.get)
        tests = b.checkbox("Run unit tests", value=True)
        if c.button("Validate approved fixes", type="primary",
                    disabled=not approved, width="stretch"):
            run_workflow(repo, out, "validate", "Running the sandbox: build, test, rescan…", mode=mode, run_tests=tests)
            st.rerun()
        st.caption("The app's own build and tests run inside the sandbox copy; dependency install scripts never run. "
                   "Verified fixes from dashboard imports are published to a private GitHub branch. Juice Shop takes about a minute per fix.")
    val = d["val"]
    if not val:
        return
    vdir = out / val["dir"]
    rc = val.get("combined")
    st.markdown(f"### Latest run `{val['run']}` from commit `{val['base_commit'][:9]}`")
    if rc:
        dd = rc.get("diff") or {}
        st.markdown(f'<span class="verdict" style="--c:{VERDICT.get(rc.get("verdict"), MUTED)}">{escape(rc.get("verdict", "?"))}</span>'
                    f'<b>Release candidate</b> with {", ".join(rc["actions"])} on branch <code>{escape(rc["branch"])}</code>. '
                    f'{escape("; ".join(rc.get("reasons") or []))}', unsafe_allow_html=True)
        if dd:
            sb, sa = dd.get("severity_before", {}), dd.get("severity_after", {})
            st.markdown('<div class="big2">' + "".join(
                f'<div><div class="k">{k}</div><div class="v">' + (f'<s>{escape(str(b_))}</s>' if b_ != "–" else "") + f'{escape(str(a_))}</div></div>' for k, b_, a_ in [
                    ("Advisories", dd["advisories_before"], dd["advisories_after"]),
                    ("Critical / high", f"{sb.get('critical', 0)}/{sb.get('high', 0)}", f"{sa.get('critical', 0)}/{sa.get('high', 0)}"),
                    ("SBOM components", dd["sbom_components_before"], dd["sbom_components_after"]),
                    ("Installed packages", dd["packages_before"], dd["packages_after"]),
                    ("New advisories", "–", len(dd["new_vulnerabilities"])),
                    ("New dependency names", "–", len(dd["new_dependencies"]))]) + "</div>", unsafe_allow_html=True)
    cases = val.get("cases") or ([rc] if rc else [])
    plan = {a["id"]: a for a in d["plan"]["actions"]}
    st.markdown("### Fix by fix")
    rows = []
    for ccase in cases:
        st_ = {s["step"]: s["status"] for s in ccase["steps"]}
        t = ccase.get("tests") or {}
        dd = ccase.get("diff") or {}
        rows.append({"fix": ", ".join(ccase["actions"]), "what": "; ".join(plan[a]["title"] for a in ccase["actions"] if a in plan)[:90],
                     "verdict": ccase.get("verdict"), "build": st_.get("Build"), "tests": f"{t.get('passed')} ok / {t.get('failed')} failed" if t else st_.get("Unit tests"),
                     "advisories": f"{dd.get('advisories_before')} → {dd.get('advisories_after')}" if dd else "",
                     "resolved": len(dd.get("resolved", [])) if dd else None, "new": len(dd.get("new_vulnerabilities", [])) if dd else None,
                     "why": "; ".join(ccase.get("reasons") or [])})
    bt = val["baseline"].get("tests") or {}
    st.caption(f"Baseline (no changes): build {next((s['status'] for s in val['baseline']['steps'] if s['step'] == 'Build'), '?')}, "
               f"tests {bt.get('passed')} passed / {bt.get('failed')} failed.")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    for ccase in cases + [val["baseline"]]:
        if not ccase:
            continue
        v = ccase.get("verdict") or "reference run"
        with st.expander(f"{ccase['name']} · {v}"):
            st.markdown('<div class="stepchips">' + "".join(
                f'<span style="background:{GREEN if s["status"] == "pass" else RED if s["status"] == "fail" else MUTED}">'
                f'{escape(s["step"])} {"✓" if s["status"] == "pass" else "✕" if s["status"] == "fail" else "·"}</span>' for s in ccase["steps"])
                + "</div>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{k: s[k] for k in ("step", "status", "seconds", "detail")} for s in ccase["steps"]]),
                         hide_index=True, width="stretch")
            if ccase.get("applied"):
                st.markdown("**Applied:** " + "; ".join(f"`{x}`" for x in ccase["applied"]))
            t = ccase.get("tests") or {}
            if t.get("failing"):
                st.markdown("**Tests that fail with this change:**")
                st.code("\n".join(t["failing"][:15]), language="text")
            dd = ccase.get("diff") or {}
            if dd:
                l, r = st.columns(2)
                with l:
                    st.markdown(f"**Resolved ({len(dd['resolved'])})**")
                    if dd["resolved"]:
                        st.dataframe(pd.DataFrame(dd["resolved"]), hide_index=True, width="stretch", height=180)
                    st.markdown(f"**SBOM: {len(dd['sbom_added'])} added, {len(dd['sbom_removed'])} removed** "
                                f"({dd['sbom_components_before']} → {dd['sbom_components_after']} components)")
                    if dd["sbom_added"] or dd["sbom_removed"]:
                        st.dataframe(pd.DataFrame({"change": ["added"] * len(dd["sbom_added"]) + ["removed"] * len(dd["sbom_removed"]),
                                                   "component": dd["sbom_added"] + dd["sbom_removed"]}), hide_index=True, width="stretch", height=180)
                with r:
                    st.markdown(f"**Newly introduced advisories ({len(dd['new_vulnerabilities'])})**")
                    if dd["new_vulnerabilities"]:
                        st.dataframe(pd.DataFrame(dd["new_vulnerabilities"]), hide_index=True, width="stretch", height=180)
                    else:
                        st.markdown("None.")
                    st.markdown(f"**New dependency names ({len(dd['new_dependencies'])})**: " + (", ".join(f"`{n}`" for n in dd["new_dependencies"][:20]) or "none"))
                    if dd["targeted_still_vulnerable"]:
                        st.markdown("**Still vulnerable:** " + ", ".join(f"`{p}`" for p in dd["targeted_still_vulnerable"]))
            if ccase.get("patch") and (vdir / ccase["patch"]).exists():
                patch = (vdir / ccase["patch"]).read_text(encoding="utf-8")
                st.markdown(f"**Patch** (lockfile: {ccase.get('lockfile_diff')}) · branch `{ccase['branch']}` · commit `{(ccase.get('commit') or '')[:9]}`")
                st.code(patch[:3000] or "(empty)", language="diff")
                st.download_button("Download .patch", patch, f"{ccase['name'].replace(' ', '-')}.patch", key=f"dl_{ccase['name']}")
                st.markdown(f"Rollback after merging: `git revert {(ccase.get('commit') or '')[:9]}`. To inspect the branch: "
                            f"`git -C target\\{repo.name} log {ccase['branch']}`")
            logs = [s for s in ccase["steps"] if s.get("log")]
            if logs:
                pick = st.selectbox("Log", [s["step"] for s in logs], key=f"log_{ccase['name']}")
                lf = vdir / next(s["log"] for s in logs if s["step"] == pick)
                if lf.exists():
                    st.code(lf.read_text(encoding="utf-8", errors="replace")[-6000:], language="text")
    git_panel(repo, out)


def journey_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## Detection → verified fix")
    lead("The Day 2 final demonstration: pick one finding and follow it from the moment it was detected to a verified "
         "remediation, with the evidence at every step.")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    rep = d["report"]
    if not rep:
        st.info("Build the verified report first (Day 2 overview → Rebuild the verified report).")
        return
    js = rep["journeys"]
    order = {"Verified remediation": 0}
    js_sorted = sorted(js, key=lambda j: (order.get(j["status"], 1), -j["score"]))
    pick = st.selectbox("Finding", [j["risk"] for j in js_sorted],
                        format_func=lambda r: next(f"{j['risk']} · {j['subject'][:70]} · {j['status']}" for j in js if j["risk"] == r))
    j = next(x for x in js if x["risk"] == pick)
    risk = next(i for i in d["risks"]["items"] if i["id"] == pick)
    act = next((a for a in d["plan"]["actions"] if a["id"] == j["action"]), None)
    val = d["val"] or {}
    case = None
    for c in val.get("cases", []) + ([val["combined"]] if val.get("combined") else []):
        if j["action"] in c.get("actions", []):
            case = c if c.get("name") != "release candidate" or case is None else case
    rc = val.get("combined") if val.get("combined") and j["action"] in val["combined"].get("actions", []) else None
    ev = risk["evidence"]

    def stop(color, title, body, meta=""):
        return f'<div class="stop" style="--c:{color}"><div class="t">{title}</div><div class="d">{body}</div><div class="m">{meta}</div></div>'
    html = '<div class="journey">'
    if risk["kind"] == "vulnerability":
        adv = ev["advisories"][0]
        html += stop(BLUE, "1 · Detected", escape(f"Agent 4 found {len(ev['advisories'])} advisor{'y' if len(ev['advisories']) == 1 else 'ies'} for "
                                                f"{ev['package']}, worst {adv['id']} ({adv['severity']}): {adv['title'][:120]}"),
                     escape("Path: " + " → ".join(ev["dependency_path"])))
    else:
        html += stop(BLUE, "1 · Detected", escape(risk["subject"]), escape("; ".join(f["fact"] for f in ev.get("facts", [])[:2])[:300]))
    html += stop(TIER[risk["tier"]], f"2 · Prioritised: {risk['tier']} {risk['score']}",
                 factor_bar(risk["factors"]) + escape(risk["reasoning"]),
                 escape(f"{risk['reasoning_source']} · confidence {risk['confidence_label']} ({risk['confidence']})"))
    if act:
        html += stop(BLUE, "3 · Recommended fix", escape(f"{act['id']} {act['title']}. {act['expected_risk_reduction'].get('statement', '')}"),
                     escape(f"Compatibility {act['compatibility'].get('level')}: {act['compatibility'].get('summary', '')}"))
    else:
        html += stop(MUTED, "3 · Recommended fix", "No action planned for this risk.")
    dd = j.get("decision")
    if dd:
        col, lab = DECISION[dd["decision"]]
        html += stop(col, f"4 · Human decision: {lab}", escape(f"by {dd['reviewer']} on {dd['at'][:16].replace('T', ' ')} UTC"
                                                                  + (f" — “{dd['comment']}”" if dd.get("comment") else "")
                                                                  + (f" (review by {dd['expires']})" if dd.get("expires") else "")))
    else:
        html += stop(MUTED, "4 · Human decision", "Waiting for a reviewer on page 7.")
    if case:
        t = case.get("tests") or {}
        steps = {s["step"]: s for s in case["steps"]}
        html += stop(VERDICT.get(case.get("verdict"), MUTED), f"5 · Build & test: {case.get('verdict')}",
                     escape("; ".join(case.get("reasons") or [])[:400]),
                     escape(f"branch {case['branch']} · build {steps.get('Build', {}).get('status')} · tests {t.get('passed')} passed, {t.get('failed')} failed"))
        diff = case.get("diff") or {}
        if diff:
            gone = risk["kind"] != "vulnerability" or risk["subject"] not in diff.get("targeted_still_vulnerable", [])
            html += stop(GREEN if gone else RED, "6 · Rescan",
                         escape(f"Advisories {diff['advisories_before']} → {diff['advisories_after']}; "
                                f"{risk['subject'] if risk['kind'] == 'vulnerability' else 'the finding'} {'no longer appears' if gone else 'is still present'}; "
                                f"{len(diff['new_vulnerabilities'])} new advisories, {len(diff['new_dependencies'])} new dependency names."),
                         escape(f"SBOM {diff['sbom_components_before']} → {diff['sbom_components_after']} components"))
    elif dd and dd["decision"] == "approve":
        html += stop(MUTED, "5 · Build & test", "Approved but not validated yet: run it on page 8 · Validation.")
    final_col = GREEN if j["status"] == "Verified remediation" else AMBER if "accepted" in j["status"].lower() or "Escalated" in j["status"] else RED if "failed" in j["status"].lower() else MUTED
    html += stop(final_col, f"7 · Outcome: {j['status']}",
                 escape(f"In release candidate {rc['branch']} ({(rc.get('commit') or '')[:9]}). Not merged: a person decides." if rc and j["status"] == "Verified remediation" else ""))
    st.markdown(html + "</div>", unsafe_allow_html=True)


def report_page(repo: Path, out: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## 8 · Verified report & audit trail")
    lead("The complete story: original finding and evidence, recommended and approved action, build and test results, "
         "before-and-after risk, what remains or was accepted, final confidence, and a tamper-evident audit trail.")
    d = load_d2(out)
    if not need_plan(d, repo, out):
        return
    a, b = st.columns([1, 1])
    if a.button("Rebuild the verified report", type="primary", width="stretch"):
        from guardian.day2 import verify_report
        verify_report.build(out, repo.name)
        st.rerun()
    pdf = day2_dir(out) / "verified_report.pdf"
    if pdf.exists():
        b.download_button("⬇  Verified report PDF", pdf.read_bytes(), f"{repo.name}-verified-remediation.pdf", "application/pdf", width="stretch")
    r = d["report"]
    if not r:
        st.info("No report yet: press Rebuild.")
        return
    s = r["summary"]
    col = {"High": GREEN, "Medium": AMBER, "Low": RED}[s["final_confidence_label"]]
    st.markdown(f'<div class="stamp" style="--c:{col}"><div class="grade">{s["final_confidence"]:.2f}</div>'
                f'<div class="verdict">{s["final_confidence_label"]} confidence<span>{s["risks_resolved"]} of {s["risks_total"]} risks verified resolved</span></div></div>',
                unsafe_allow_html=True)
    st.markdown("Because " + escape("; ".join(s["final_confidence_reasons"])) + ".")
    bb, aa = s["before"], s["after"]
    st.markdown('<div class="big2">' + "".join(
        f'<div><div class="k">{k}</div><div class="v"><s>{escape(str(x))}</s>{escape(str(y))}</div></div>' for k, x, y in [
            ("Advisories", bb.get("advisories", "–"), aa.get("advisories", "–")), ("Grade", bb.get("grade", "–"), aa.get("grade", "–")),
            ("Risk points", bb["risk_points"], aa["risk_points"]), ("Risks remaining", s["risks_total"], s["risks_remaining"])]) + "</div>",
        unsafe_allow_html=True)
    fo = r.get("final_output")
    st.markdown("### Final output: the validated fix, committed")
    if not fo:
        st.markdown("No release candidate passed validation yet, so there is no committed fix. Approve fixes on page 7 and validate them on page 8 · Validation.")
    else:
        fdir = out / fo["dir"]
        st.markdown(f"Every fix that passed is committed together on branch `{fo['branch']}` (commit `{fo['commit'][:12]}`) inside "
                    f"`target/{repo.name}`. Review the commit before merging.")
        from guardian.day2 import preview
        key = preview.identity(repo, fo["commit"])
        with st.expander("Run the approved application", expanded=True):
            st.caption("Start the validated branch in Docker on this machine. The preview installs the project's npm dependencies and runs its start or dev script.")
            if st.button("Run approved branch", key="run_" + key):
                try:
                    with st.spinner("Installing dependencies and starting the application…"):
                        st.session_state[key] = preview.launch(repo, out, fo["commit"])
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as err:
                    st.session_state.pop(key, None)
                    st.error(str(err))
            if st.session_state.get(key):
                st.link_button("Open application", st.session_state[key])
            if st.button("Stop preview", key="stop_" + key):
                try:
                    preview.stop(key)
                    st.session_state.pop(key, None)
                    st.rerun()
                except (RuntimeError, OSError, subprocess.SubprocessError) as err:
                    st.error(str(err))
        if fo.get("published_url"):
            st.link_button("Open validated branch on GitHub", fo["published_url"])
        elif fo.get("publish_error"):
            st.warning(f"GitHub publishing pending. {fo['publish_error']} Rebuild the verified report to retry.")
        st.markdown(f"Fixes in it: {', '.join(fo['actions'])} · files changed: {', '.join(fo['files_changed']) or 'see patch'}")
        if (fdir / "release-candidate.patch").exists():
            st.code((fdir / "release-candidate.patch").read_text(encoding="utf-8")[:2500], language="diff")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(fdir.glob("*")):
                z.write(f, f.name)
        c1, c2 = st.columns(2)
        c1.download_button("⬇  Final output (patches, fixed files, FINAL.md)", buf.getvalue(), f"{repo.name}-validated-fix.zip",
                           "application/zip", type="primary", width="stretch")
        if c2.button("Open the fixed code as its own folder", width="stretch"):
            try:
                from guardian.day2 import final_output
                dest = final_output.check_out(out, st.session_state.get("reviewer", ""))
                st.success(f"Checked out to {dest}. Your original copy is untouched. It also appears in the repository list, so you can inspect it.")
            except ValueError as err:
                st.error(f"{err} Enter your name on page 7 first.")
        if fo.get("worktree"):
            st.caption(f"Fixed code folder: {fo['worktree']}")
        st.code(f"git -C target\\{repo.name} show --stat {fo['commit'][:12]}\n"
                f"git -C target\\{repo.name} merge --no-ff {fo['branch']}     :: apply, after review\n"
                f"git -C target\\{repo.name} revert -m 1 HEAD                 :: undo after merging", language="bat")
    if fo:
        git_panel(repo, out)
    st.markdown("### Finding by finding")
    st.dataframe(pd.DataFrame([{"risk": j["risk"], "subject": j["subject"], "tier": j["tier"], "score": j["score"],
                                "action": j["action_title"] or "", "decision": f"{j['decision']['decision']} · {j['decision']['reviewer']}" if j["decision"] else "",
                                "validation": (j["validation"] or {}).get("verdict") or "", "status": j["status"]} for j in r["journeys"]]),
                 hide_index=True, width="stretch", height=380)
    st.markdown("### Remaining and accepted risk")
    rem = [j for j in r["journeys"] if j["status"] != "Verified remediation"]
    if rem:
        st.dataframe(pd.DataFrame([{"risk": j["risk"], "subject": j["subject"], "tier": j["tier"], "status": j["status"],
                                    "reason": (j["decision"] or {}).get("comment", "")} for j in rem]), hide_index=True, width="stretch")
    if r.get("expired_acceptances"):
        st.warning("Accepted risks past their review date: " + ", ".join(r["expired_acceptances"]))
    ok, msg = verify_audit(out)
    st.markdown("### Audit trail " + chip("chain intact" if ok else "chain broken", GREEN if ok else RED), unsafe_allow_html=True)
    st.caption(msg + ". Every entry stores the hash of the one before it, so editing or deleting history is detected.")
    st.dataframe(pd.DataFrame([{"#": e["seq"], "time (UTC)": e["at"][:19].replace("T", " "), "actor": e["actor"], "event": e["event"],
                                "details": json.dumps(e["details"])[:160], "hash": e["hash"][:12]} for e in read_audit(out)][::-1]),
                 hide_index=True, width="stretch", height=300)
    st.markdown("### Responsible AI and security")
    ra = r["responsible_ai"]
    st.markdown(f"Reasoning: **{escape(ra['provider'])}** · {ra['calls']} LLM calls, {ra['accepted_answers']} answers passed the grounding check.")
    for c in ra["controls"]:
        st.markdown(f"- {c}")
    files = [("verified_report.json", "application/json"), ("verified_report.md", "text/markdown"), ("audit_log.jsonl", "text/plain"),
             ("llm_log.jsonl", "text/plain"), ("remediation_plan.json", "application/json"), ("decisions.json", "application/json")]
    cols = st.columns(3)
    for k, (name, mime) in enumerate(files):
        p = day2_dir(out) / name
        if p.exists():
            cols[k % 3].download_button(name, p.read_bytes(), name, mime, width="stretch", key=f"dl2_{name}")


# ---------------- benchmark ----------------
CAPABILITIES = [  # from each tool's own documentation; shown separately from what was measured
    ("Finds known vulnerabilities in npm lockfiles", True, True, True, True, True),
    ("Merges CVE/GHSA ids for the same bug", True, "n/a (GHSA only)", True, True, True),
    ("Shows how each vulnerable package got in", True, "node paths", False, False, "--dependency-tree"),
    ("Generates an SBOM", True, "npm sbom", False, "via Syft", True),
    ("Prioritises by exploit data", "EPSS/KEV + reachability + exposure", False, False, "EPSS/KEV", False),
    ("Detects typosquats, install scripts, lockfile tampering", True, False, False, False, False),
    ("Checks container image and CI action pinning", True, False, False, False, "Dockerfile config scan"),
    ("Proposes a fix", "with compatibility + rollback", "npm audit fix", "guided remediation", False, False),
    ("Human approval before any change", True, False, False, False, False),
    ("Builds, tests and rescans the fix in a sandbox", True, False, False, False, False),
    ("Evidence report with tamper-evident audit trail", True, False, False, False, False),
]


def benchmark_page(root: Path):
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown("## Benchmark · the Guardian vs other tools")
    lead("Every installed scanner runs on the <b>same lockfile</b>. Findings are matched as (package, version, vulnerability), "
         "with CVE and GHSA ids for the same bug merged. A finding is <b>confirmed</b> when at least two independent databases "
         "(npm audit, OSV, Grype, Trivy) report it; precision, recall and F1 are measured against that consensus. "
         "The Guardian is not a voter, because it reuses OSV and npm audit.")
    from guardian.agents.sbom import find_tool
    from guardian.benchmark import BENCH, TOOLS
    have = {t: t in ("guardian", "npm-audit") or bool(find_tool(t)) for t in TOOLS}
    st.markdown("Tools on this machine: " + "".join(chip(t, GREEN if v else MUTED) for t, v in have.items()), unsafe_allow_html=True)
    if not all(have.values()):
        st.caption("Missing tools are skipped. Run `benchmark_tools.bat` once to download Grype and Trivy into tools\\ "
                   "(OSV-Scanner comes with setup.bat). Precision and recall need at least two independent scanners.")
    targets = [p.name for p in sorted((root / "target").iterdir()) if (p / "package-lock.json").exists()] if (root / "target").exists() else []
    a, b = st.columns([2, 1])
    pick = a.multiselect("Repositories", targets, [t for t in targets if t == "juice-shop"] or targets[:1])
    ctrl = b.checkbox("Include the controlled non-CVE test", value=True)
    if st.button("Run the benchmark", type="primary", disabled=not pick):
        from guardian import benchmark
        with st.status("Running every tool on the same lockfiles…", expanded=True) as status:
            benchmark.run([root / "target" / n for n in pick], log=lambda m: status.write(f"`{m}`"), controlled=ctrl)
            status.update(label="Benchmark finished", state="complete", expanded=False)
        st.rerun()
    data = read_json(BENCH / "benchmark.json")
    if not data:
        st.info("No results yet. Choose repositories and press Run the benchmark (a few minutes per repository).")
        return
    st.caption(f"Last run {data['generated_at']}")
    st.markdown("### What the numbers say")
    for line in data.get("analysis", []):
        st.markdown(f"- {escape(line)}")
    for name, r in data["repos"].items():
        st.markdown(f"### {name}")
        st.markdown(f"Reference: **{r['reference_size']}** findings {escape(r['reference_rule'])} "
                    f"({r['reference_prod']} in production packages). Voters: {', '.join(r['voters']) or 'none'}.")
        if r["single_source"]:
            st.warning("Only one independent scanner ran, so every tool is compared with that one database. Install more scanners for real precision/recall.")
        ok = {t: m for t, m in r["metrics"].items() if m.get("status") == "ok"}
        prod = st.toggle("Production packages only", key=f"prod_{name}")
        sfx = "_prod" if prod else ""
        tbl = pd.DataFrame([{"tool": t, "version": m.get("version", ""), "findings": m["unique_findings"], "raw rows": m["raw_rows"],
                             "duplicates merged": m["duplicates_merged"], "confirmed (TP)": m["tp"], "unconfirmed (FP)": m["fp"],
                             "missed (FN)": m["fn"], "precision": m["precision" + sfx], "recall": m["recall" + sfx], "F1": m["f1" + sfx],
                             "severity agrees": m["severity_agreement"], "has fix": m["with_fix"], "has path": m["with_path"],
                             "seconds": m["seconds"]} for t, m in ok.items()])
        st.dataframe(tbl, hide_index=True, width="stretch",
                     column_config={c: st.column_config.ProgressColumn(c, min_value=0, max_value=1, format="%.2f")
                                    for c in ("precision", "recall", "F1", "severity agrees", "has fix", "has path")})
        for t, m in r["metrics"].items():
            if m.get("status") != "ok":
                st.caption(f"{t}: {m.get('status')} — {m.get('note', '')}")
        long = tbl.melt(id_vars="tool", value_vars=["precision", "recall", "F1"], var_name="metric", value_name="value")
        l, rr = st.columns([3, 2], gap="large")
        with l:
            st.altair_chart(alt.Chart(long).mark_bar().encode(
                y=alt.Y("tool:N", title=None), x=alt.X("value:Q", scale=alt.Scale(domain=[0, 1]), title=None),
                color=alt.Color("metric:N", scale=alt.Scale(range=[BLUE, GREEN, AMBER]), legend=alt.Legend(orient="bottom", title=None)),
                yOffset="metric:N", tooltip=["tool", "metric", "value"]).properties(height=alt.Step(14)), width="stretch")
        with rr:
            ov = pd.DataFrame([{"a": k.split("|")[0], "b": k.split("|")[1], "jaccard": v} for k, v in r["overlap"].items()])
            if not ov.empty:
                st.altair_chart(alt.Chart(ov).mark_rect().encode(
                    x=alt.X("a:N", title=None), y=alt.Y("b:N", title=None),
                    color=alt.Color("jaccard:Q", scale=alt.Scale(scheme="blues", domain=[0, 1]), legend=None),
                    tooltip=["a", "b", "jaccard"]).properties(height=220, title="How much the tools agree (Jaccard)"), width="stretch")
        with st.expander("Examples of unconfirmed and missed findings"):
            for t, m in ok.items():
                if m["unconfirmed_examples"] or m["missed_examples"]:
                    st.markdown(f"**{t}** unconfirmed: " + (", ".join(f"`{x}`" for x in m["unconfirmed_examples"][:6]) or "none")
                                + "  \nmissed: " + (", ".join(f"`{x}`" for x in m["missed_examples"][:6]) or "none"))
    c = data.get("controlled")
    if c:
        st.markdown("### Controlled test: non-CVE supply-chain attacks")
        st.markdown(escape(c["note"]) + " Each case was written to exercise one check, so this measures coverage of attack types, "
                    "not real-world accuracy. Two harmless changes check for false alarms.")
        rows = []
        for case in c["cases"]:
            rows.append({"case": case["label"], **{t: ("✓" if v else "✕" if v is False else "n/a") for t, v in case["detected"].items()}})
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.dataframe(pd.DataFrame([{"tool": t, "caught": f"{s['detected']} of {s['planted']}", "recall": s["recall"],
                                    "false alarms": f"{s['false_alarms']} of {s['controls']}"} for t, s in c["summary"].items() if s]),
                     hide_index=True, width="stretch")
    st.markdown("### Capabilities (our reading of each tool's documentation, not measured: check before quoting)")
    st.dataframe(pd.DataFrame([{"capability": row[0], **{t: ("✓" if v is True else "✕" if v is False else v)
                                                         for t, v in zip(["Guardian", "npm audit", "OSV-Scanner", "Grype", "Trivy"], row[1:])}}
                               for row in CAPABILITIES]), hide_index=True, width="stretch")
