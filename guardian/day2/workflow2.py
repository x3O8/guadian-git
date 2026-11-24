"""Day 2 orchestration (LangGraph): three agents and one human gate.

    START ─► 6 Risk Analysis ─► 7 Remediation ─► Human approval gate ──(nothing approved: stop, wait)──► END
             (prioritise +       (fix plan)            │ approved
              investigate)                             ▼
                                              8 Validation & Report ─► END
                                              (sandbox build/test/rescan, commit, verified report)

phase="plan" runs agents 6-7 and stops at the gate: the plan waits for a person. phase="validate" starts at
the gate, reads the recorded decisions and runs agent 8 (validation only for approved actions, then the report).
Agents pass typed state (Pydantic models serialised to dicts) through GuardianDay2State.
"""
import operator
import traceback
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from guardian.day2 import approvals, investigate, prioritize, remediate, validate, verify_report
from guardian.day2.common import audit, load_day1, read_json, day2_dir
from guardian.models import AgentLog

AGENTS2 = ["6. Risk Analysis Agent", "7. Remediation Agent", "Human approval gate", "8. Validation & Report Agent"]


class GuardianDay2State(TypedDict, total=False):
    repo: str
    out_dir: str
    phase: str               # plan | validate
    use_llm: bool
    mode: str                # each | together
    run_tests: bool
    risks: Any
    investigations: Any
    plan: Any
    approved: list
    validation: Optional[dict]
    report: Optional[dict]
    log_fn: Any
    log: Annotated[list, operator.add]
    errors: Annotated[list, operator.add]


def node(name: str):
    def wrap(fn):
        def run(state: GuardianDay2State):
            out = Path(state["out_dir"])
            try:
                update, msg = fn(state, Path(state["repo"]), out)
                audit(out, f"agent:{name}", "agent-finished", {"message": msg})
                return {**update, "log": [AgentLog(agent=name, status="ok", message=msg)]}
            except Exception as err:
                traceback.print_exc()
                audit(out, f"agent:{name}", "agent-failed", {"error": str(err)[:500]})
                return {"log": [AgentLog(agent=name, status="error", message=str(err))], "errors": [f"{name}: {err}"]}
        return run
    return wrap


@node(AGENTS2[0])
def risk_analysis_node(state, repo, out):
    """Prioritise every known vulnerability, investigate non-CVE risks, and put both on one scale."""
    d1 = load_day1(out)
    use_llm = state.get("use_llm", True)
    risks = prioritize.prioritise(repo, d1, use_llm=use_llm)
    invs = investigate.investigate(repo, d1, use_llm=use_llm)
    risks = prioritize.add_supply_chain(out, risks, invs)
    tiers, v = {}, {}
    for i in risks["items"]:
        tiers[i["tier"]] = tiers.get(i["tier"], 0) + 1
    for i in invs["items"]:
        v[i["verdict"]] = v.get(i["verdict"], 0) + 1
    return {"risks": risks, "investigations": invs}, (
        f"{len(risks['items'])} risks scored (" + ", ".join(f"{n} {t}" for t, n in tiers.items()) + "); "
        f"{len(invs['items'])} non-CVE checks: " + ", ".join(f"{n} {k.lower()}" for k, n in v.items()))


@node(AGENTS2[1])
def remediate_node(state, repo, out):
    d1 = load_day1(out)
    p = remediate.plan(repo, d1, state["risks"], state["investigations"], use_llm=state.get("use_llm", True))
    auto = sum(a["auto_applicable"] for a in p["actions"])
    return {"plan": p}, f"{len(p['actions'])} actions proposed ({auto} can be validated automatically, {len(p['actions']) - auto} need a human fix or decision)"


@node(AGENTS2[2])
def gate_node(state, repo, out):
    s = approvals.summary(out)
    approved = approvals.approved_actions(out) if state.get("phase") == "validate" else []
    msg = (f"{s['approve']} approved, {s['reject']} rejected, {s['accept-risk']} accepted, {s['escalate']} escalated, "
           f"{s['pending']} waiting for a decision")
    if state.get("phase") != "validate":
        msg = "plan ready; waiting for a human decision. " + msg
    return {"approved": approved}, msg


@node(AGENTS2[3])
def validate_report_node(state, repo, out):
    """Validate the approved fixes in the sandbox (commit them, attributed to the approver), then write the verified report."""
    msg = "nothing approved, so nothing validated"
    res = None
    if state.get("approved"):
        res = validate.validate(repo, out, state["approved"], mode=state.get("mode", "each"),
                                run_tests=state.get("run_tests", True), log=state.get("log_fn") or print)
        rc = res.get("combined") or {}
        msg = (f"{len(res['passed'])} of {len(res['approved'])} approved fixes passed; release candidate "
               f"{rc.get('verdict', 'none')}" + (f" on {rc['branch']}" if rc.get("branch") else ""))
    r = verify_report.build(out, Path(state["repo"]).name)
    s = r["summary"]
    return {"validation": res, "report": r}, (f"{msg}; report: {s['risks_resolved']} risks verified resolved, "
                                              f"{s['risks_remaining']} remaining, confidence {s['final_confidence_label']} ({s['final_confidence']})")


def route_start(state):
    return "human_approval_gate" if state.get("phase") == "validate" else "risk_analysis"


def route_gate(state):
    return "validation_report" if state.get("phase") == "validate" else END  # the plan stops here until a person decides


def build_graph():
    g = StateGraph(GuardianDay2State)
    g.add_node("risk_analysis", risk_analysis_node)
    g.add_node("remediation", remediate_node)
    g.add_node("human_approval_gate", gate_node)
    g.add_node("validation_report", validate_report_node)
    g.add_conditional_edges(START, route_start, ["risk_analysis", "human_approval_gate"])
    g.add_edge("risk_analysis", "remediation")
    g.add_edge("remediation", "human_approval_gate")
    g.add_conditional_edges("human_approval_gate", route_gate, ["validation_report", END])
    g.add_edge("validation_report", END)
    return g.compile()


def stream(repo: str, out_dir: str, phase: str, use_llm: bool = True, mode: str = "each", run_tests: bool = True, log=print):
    """Yield ("log", AgentLog) as each step finishes, then ("done", state)."""
    state0 = {"repo": str(Path(repo).resolve()), "out_dir": str(Path(out_dir).resolve()), "phase": phase,
              "use_llm": use_llm, "mode": mode, "run_tests": run_tests, "log": [], "errors": [], "log_fn": log}
    audit(Path(out_dir), "workflow", f"day2-{phase}-started", {"repo": Path(repo).name, "llm": use_llm})
    seen, state = 0, None
    for state in build_graph().stream(state0, stream_mode="values"):
        for e in state.get("log", [])[seen:]:
            yield "log", e
        seen = len(state.get("log", []))
    yield "done", state


def run(repo: str, out_dir: str, phase: str, **kw):
    final = None
    for kind, item in stream(repo, out_dir, phase, **kw):
        if kind == "log":
            print(f"{item.agent}: {item.status} - {item.message}")
        else:
            final = item
    return final
