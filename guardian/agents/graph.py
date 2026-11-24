import json
from pathlib import Path

import networkx as nx

from guardian.lockfile import edges, load_lock
from guardian.tree_html import render_tree
from guardian.models import GraphSummary, Inventory

ROOT = "ROOT"


def node_id(path: str) -> str:
    return path or ROOT


def build_graph(repo: Path, inv: Inventory) -> tuple[nx.DiGraph, list[str]]:
    packages = load_lock(repo)["packages"]
    by_path = {c.lock_path: c for c in inv.npm()}
    g = nx.DiGraph()
    g.add_node(ROOT, name=inv.app_name, version=inv.app_version, direct=False, scope="root",
               label=f"{inv.app_name}@{inv.app_version}")
    for path, c in by_path.items():
        g.add_node(path, name=c.name, version=c.version, direct=c.direct, scope=c.scope,
                   label=f"{c.name}@{c.version}")
    unresolved = []
    for parent, child, dep, rng, field in edges(packages):
        if parent and parent not in by_path:
            continue
        if child is None:
            if field == "dependencies":
                unresolved.append(f"{node_id(parent)} -> {dep}@{rng}")
            continue
        if parent == "" and field == "peerDependencies":
            continue
        g.add_edge(node_id(parent), child, range=rng, type=field)
    for path, c in by_path.items():
        if c.direct and not g.has_edge(ROOT, path):
            g.add_edge(ROOT, path, range=c.declared_range, type="dependencies")
    return g, unresolved


def shortest_path(g: nx.DiGraph, node: str) -> list[str]:
    try:
        return [g.nodes[n]["label"] for n in nx.shortest_path(g, ROOT, node)]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def introduced_via(g: nx.DiGraph, node: str) -> list[str]:
    if g.nodes[node].get("direct"):
        return [g.nodes[node]["label"]]
    anc = nx.ancestors(g, node)
    return sorted(g.nodes[n]["label"] for n in g.successors(ROOT) if n in anc)


def sample_paths(g: nx.DiGraph, node: str, limit: int = 5, cutoff: int = 12) -> list[list[str]]:
    paths = []
    for p in nx.all_simple_paths(g, ROOT, node, cutoff=cutoff):
        paths.append([g.nodes[n]["label"] for n in p])
        if len(paths) >= limit:
            break
    return sorted(paths, key=len)


def find_nodes(g: nx.DiGraph, name: str, version: str = None) -> list[str]:
    return [n for n, d in g.nodes(data=True)
            if d.get("name") == name and (version is None or d.get("version") == version)]


def write_json(g: nx.DiGraph, unresolved: list[str], out_file: Path):
    nodes = []
    for n, d in g.nodes(data=True):
        nodes.append({"id": n, **d, "parents": [g.nodes[p]["label"] for p in g.predecessors(n)],
                      "children": len(list(g.successors(n))),
                      "shortest_path": shortest_path(g, n) if n != ROOT else [d["label"]],
                      "introduced_via": introduced_via(g, n) if n != ROOT else []})
    data = {"root": ROOT, "nodes": nodes,
            "edges": [{"from": u, "to": v, **d} for u, v, d in g.edges(data=True)],
            "unresolved_edges": unresolved}
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


def render_html(g: nx.DiGraph, out_file: Path, highlight: set = frozenset()) -> Path:
    return render_tree(g, out_file, highlight)


def build_dependency_graph(repo: Path, out_dir: Path, inv: Inventory):
    g, unresolved = build_graph(repo, inv)
    json_file, html_file = out_dir / "dependency_graph.json", out_dir / "dependency_graph.html"
    write_json(g, unresolved, json_file)
    render_html(g, html_file)
    direct = len(list(g.successors(ROOT)))
    summary = GraphSummary(json_path=str(json_file), html_path=str(html_file),
                           nodes=g.number_of_nodes(), edges=g.number_of_edges(), direct=direct,
                           transitive=g.number_of_nodes() - 1 - direct, unresolved_edges=unresolved)
    return g, summary


def node_for_package(g: nx.DiGraph, name: str, version: str):
    matches = find_nodes(g, name, version)
    if not matches:
        return None
    return min(matches, key=lambda n: len(nx.shortest_path(g, ROOT, n)) if nx.has_path(g, ROOT, n) else 999)
