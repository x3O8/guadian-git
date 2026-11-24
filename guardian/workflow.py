import operator
import traceback
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from guardian.agents import discovery, graph, report, sbom, suspicious, vulnerability
from guardian.models import AgentLog


class GuardianState(TypedDict, total=False):
    repo: str
    out_dir: str
    base_ref: str
    scanner_choice: str
    inventory: Any
    sbom: Any
    graph: Any
    graph_obj: Any
    vulnerabilities: list
    scanner: Optional[str]
    scanner_notes: list
    suspicious: list
    suspicious_notes: list
    report: dict
    log: Annotated[list, operator.add]
    errors: Annotated[list, operator.add]


def agent(name: str, needs_inventory: bool = True):
    """Wrap an agent step: skip if prerequisites are missing, log result, capture errors."""
    def wrap(fn):
        def node(state: GuardianState):
            if needs_inventory and state.get("inventory") is None:
                return {"log": [AgentLog(agent=name, status="skipped", message="no inventory")]}
            try:
                update, msg = fn(state, Path(state["repo"]), Path(state["out_dir"]))
                return {**update, "log": [AgentLog(agent=name, status="ok", message=msg)]}
            except Exception as err:
                traceback.print_exc()
                return {"log": [AgentLog(agent=name, status="error", message=str(err))],
                        "errors": [f"{name}: {err}"]}
        return node
    return wrap


@agent("1. Repository Discovery Agent", needs_inventory=False)
def discovery_node(state, repo, out):
    inv = discovery.discover(repo, out)
    npm = inv.npm()
    return {"inventory": inv}, (f"{len(inv.manifests)} manifests, {len(npm)} npm packages "
                                f"({sum(c.direct for c in npm)} direct), "
                                f"{len(inv.components) - len(npm)} container/CI components")


@agent("2. SBOM Agent")
def sbom_node(state, repo, out):
    s = sbom.generate_sbom(repo, out, state["inventory"])
    return {"sbom": s}, f"{s.format} {s.spec_version} via {s.tool}: {s.component_count} components"


@agent("3. Dependency Analysis Agent")
def graph_node(state, repo, out):
    g, summary = graph.build_dependency_graph(repo, out, state["inventory"])
    return {"graph": summary, "graph_obj": g}, f"{summary.nodes} nodes, {summary.edges} edges"


@agent("4. Vulnerability Detection Agent")
def vuln_node(state, repo, out):
    if state.get("graph_obj") is None:
        raise RuntimeError("dependency graph missing")
    vulns, used, notes = vulnerability.scan(repo, out, state["inventory"], state["graph_obj"],
                                            state.get("scanner_choice", "auto"))
    msg = f"{len(vulns)} findings via {used}" + (f" (fallback used: {', '.join(n.split(':')[0] for n in notes)} unavailable)" if notes else "")
    return {"vulnerabilities": vulns, "scanner": used, "scanner_notes": notes}, msg


@agent("5. Anomaly Detection Agent")
def suspicious_node(state, repo, out):
    findings, notes = suspicious.detect(repo, out, state["inventory"], state.get("base_ref", "HEAD"))
    changes = sum(f.kind == "change" for f in findings)
    return ({"suspicious": findings, "suspicious_notes": notes},
            f"{changes} anomal{'y' if changes == 1 else 'ies'} vs {state.get('base_ref', 'HEAD')}, "
            f"{len(findings) - changes} baseline observations")


@agent("Report step (workflow, not an agent)")
def report_node(state, repo, out):
    r = report.build_report(state, out)
    return {"report": r}, f"report written; interpretation source: {r['interpretation']['source']}"


def build_workflow():
    wf = StateGraph(GuardianState)
    steps = [("repository_discovery", discovery_node), ("sbom", sbom_node),
             ("dependency_analysis", graph_node), ("vulnerability_detection", vuln_node),
             ("anomaly_detection", suspicious_node), ("report", report_node)]
    for name, fn in steps:
        wf.add_node(name, fn)
    wf.add_edge(START, "repository_discovery")
    for (a, _), (b, _) in zip(steps, steps[1:]):
        wf.add_edge(a, b)
    wf.add_edge("report", END)
    return wf.compile()


def initial_state(repo: str, out_dir: str, base_ref: str, scanner: str) -> dict:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    return {"repo": str(Path(repo).resolve()), "out_dir": str(Path(out_dir).resolve()),
            "base_ref": base_ref, "scanner_choice": scanner, "log": [], "errors": []}


def run(repo: str, out_dir: str, base_ref: str = "HEAD", scanner: str = "auto") -> GuardianState:
    return build_workflow().invoke(initial_state(repo, out_dir, base_ref, scanner))


def run_stream(repo: str, out_dir: str, base_ref: str = "HEAD", scanner: str = "auto"):
    """Yield ("log", AgentLog) as each agent finishes, then ("done", final_state)."""
    seen, state = 0, None
    for state in build_workflow().stream(initial_state(repo, out_dir, base_ref, scanner), stream_mode="values"):
        for entry in state.get("log", [])[seen:]:
            yield "log", entry
        seen = len(state.get("log", []))
    yield "done", state
