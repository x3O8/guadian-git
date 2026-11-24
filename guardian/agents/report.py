import os
import json
from datetime import datetime, timezone
from pathlib import Path

from guardian import llm, recommend, vuln_graph
from guardian.agents.graph import ROOT, find_nodes, render_html, sample_paths
from guardian.agents.vulnerability import SEVERITY_ORDER

SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def pick_trace(vulns, g):
    candidates = [v for v in vulns if not v.direct and v.dependency_path and v.scope == "prod"] or \
                 [v for v in vulns if not v.direct and v.dependency_path]
    if not candidates:
        return None
    v = min(candidates, key=lambda x: (SEV_RANK.get(x.severity, 9), -len(x.dependency_path)))
    nodes = find_nodes(g, v.package, v.installed_version)
    return {"vulnerability": v.id, "package": f"{v.package}@{v.installed_version}",
            "severity": v.severity, "scope": v.scope, "shortest_path": v.dependency_path,
            "introduced_via_direct_dependencies": v.introduced_via,
            "example_paths": sample_paths(g, nodes[0]) if nodes else [],
            "fixed_version": v.fixed_version, "evidence_source": v.evidence_source}


def metrics(inv, sbom, graph, vulns, suspicious):
    npm = inv.npm()
    sev = {}
    for v in vulns:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    return {"total_components": len(inv.components), "npm_packages": len(npm),
            "direct_dependencies": sum(c.direct for c in npm),
            "transitive_dependencies": sum(not c.direct for c in npm),
            "sbom_components": sbom.component_count if sbom else None,
            "graph_nodes": graph.nodes if graph else None, "graph_edges": graph.edges if graph else None,
            "vulnerabilities": len(vulns), "vulnerabilities_by_severity": sev,
            "vulnerable_prod": sum(v.scope == "prod" for v in vulns),
            "suspicious_changes": sum(f.kind == "change" for f in suspicious),
            "baseline_observations": sum(f.kind == "baseline" for f in suspicious)}


def template_summary(m, trace, vulns, suspicious, scanner):
    lines = [f"**Scope:** {m['npm_packages']} npm packages ({m['direct_dependencies']} direct, "
             f"{m['transitive_dependencies']} transitive) from package-lock.json.",
             f"**Vulnerabilities ({scanner}):** {m['vulnerabilities']} findings — "
             + ", ".join(f"{k}: {v}" for k, v in sorted(m["vulnerabilities_by_severity"].items(),
                                                        key=lambda kv: SEV_RANK.get(kv[0], 9)))
             + f". {m['vulnerable_prod']} affect production (shipped) packages."]
    top = [v for v in vulns if v.severity in ("critical", "high") and v.scope == "prod"][:5]
    if top:
        lines.append("**Highest-priority shipped findings:**")
        lines += [f"- {v.id} in {v.package}@{v.installed_version} ({v.severity}, "
                  f"{'direct' if v.direct else 'transitive via ' + ', '.join(v.introduced_via[:2])}); "
                  f"fix: {v.fixed_version or 'no fixed version in evidence'}" for v in top]
    if trace:
        lines.append(f"**Trace:** {trace['package']} ({trace['vulnerability']}) reaches the app through "
                     + " → ".join(trace["shortest_path"]) + ".")
    changes = [f for f in suspicious if f.kind == "change"]
    if changes:
        lines.append(f"**Anomalies:** {len(changes)} found:")
        lines += [f"- {f.id} [{f.severity}] {f.title} — {f.why_suspicious}" for f in changes]
    else:
        lines.append("**Anomalies:** none relative to the base ref.")
    return "\n".join(lines)


def build_report(state: dict, out_dir: Path) -> dict:
    inv, sbom, graph, g = state["inventory"], state.get("sbom"), state.get("graph"), state.get("graph_obj")
    vulns, suspicious = state.get("vulnerabilities", []), state.get("suspicious", [])
    m = metrics(inv, sbom, graph, vulns, suspicious)
    trace = pick_trace(vulns, g) if g is not None else None

    if g is not None and graph:
        vulnerable_nodes = {n for v in vulns for n in find_nodes(g, v.package, v.installed_version)}
        render_html(g, Path(graph.html_path), highlight=vulnerable_nodes)
        (out_dir / "vulnerability_graph.svg").write_text(vuln_graph.radial_svg(g, vulnerable_nodes), encoding="utf-8")

    recs = []
    deps_file = out_dir / "dependency_inventory.json"
    if vulns and deps_file.exists():
        recs = recommend.recommend([v.model_dump() for v in vulns],
                                   json.loads(deps_file.read_text(encoding="utf-8"))["dependencies"], out_dir / "raw")
        recommend.write(out_dir, recs)

    evidence = {"metrics": m, "trace": trace, "scanner": state.get("scanner"),
                "top_vulnerabilities": [v.model_dump(include={"id", "package", "installed_version", "severity",
                                        "direct", "scope", "fixed_version", "introduced_via", "title"})
                                        for v in vulns[:15]],
                "suspicious_changes": [f.model_dump() for f in suspicious]}
    fallback = template_summary(m, trace, vulns, suspicious, state.get("scanner"))
    ai = llm.interpret(evidence, "Write an executive security summary: key risks, the traced transitive "
                       "vulnerability, and each suspicious change with why it matters. Max 350 words.", fallback)

    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "repo": inv.repo,
              "commit": inv.commit, "metrics": m, "trace": trace, "interpretation": ai,
              "scanner": state.get("scanner"), "scanner_notes": state.get("scanner_notes", []),
              "sbom": sbom.model_dump() if sbom else None, "agent_log": [a.model_dump() for a in state.get("log", [])],
              "errors": state.get("errors", []),
              "fix_summary": {k: sum(r["action"] == k for r in recs) for k in sorted({r["action"] for r in recs})}}
    (out_dir / "evidence_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "evidence_report.md").write_text(to_markdown(report), encoding="utf-8")
    if not os.getenv("GUARDIAN_NO_PDF"):  # sandbox rescans during Day 2 validation skip their own PDF
        try:
            from guardian.pdf_report import build_pdf
            build_pdf(out_dir)
        except ImportError:
            print("[report] reportlab not installed; PDF skipped (pip install reportlab)")
        except Exception as err:  # a PDF problem must never break the scan
            print(f"[report] PDF not generated: {err}")
    with open(out_dir / "history.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": report["generated_at"], "commit": inv.commit,
                             "base_ref": state.get("base_ref"), "scanner": state.get("scanner"),
                             **{k: m[k] for k in ("npm_packages", "direct_dependencies", "transitive_dependencies",
                                                  "vulnerabilities", "suspicious_changes")},
                             "by_severity": m["vulnerabilities_by_severity"]}) + "\n")
    return report


def to_markdown(r: dict) -> str:
    md = [f"# Supply Chain Guardian — Evidence Report", f"Repo: `{r['repo']}`  Commit: `{r['commit']}`",
          f"Generated: {r['generated_at']}", "", "## Interpretation",
          f"_Source: {r['interpretation']['source']}_", "", r["interpretation"]["text"], "", "## Metrics"]
    md += [f"- {k}: {v}" for k, v in r["metrics"].items()]
    if r["trace"]:
        md += ["", "## Traced transitive vulnerability", f"- {r['trace']['vulnerability']} in {r['trace']['package']}",
               f"- Path: {' → '.join(r['trace']['shortest_path'])}"]
    md += ["", "## Agent log"] + [f"- {a['agent']}: {a['status']} — {a['message']}" for a in r["agent_log"]]
    return "\n".join(md)
