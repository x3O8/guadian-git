"""Radial dependency graph focused on vulnerable packages (Graphviz twopi layout).

Centre = the project. Ring 1 = direct dependencies. Outer rings = indirect levels.
Red nodes have advisories; orange edges are the paths that lead to them.
"""
import shutil
import subprocess
from pathlib import Path

import networkx as nx

ROOT = "ROOT"
INK, BLUE, RED, ORANGE, STEEL = "#1B2A3A", "#1F5FAE", "#B3261E", "#D9622B", "#5E6E7E"
LEVEL = {2: "#6F95C2", 3: "#9DB6D3", 4: "#C3D2E3"}
LEGEND = [("Project", INK), ("Direct dependency", BLUE), ("Level-2 indirect", LEVEL[2]),
          ("Level-3 indirect", LEVEL[3]), ("Level-4+ indirect", LEVEL[4]), ("Has advisories", RED)]


def vuln_paths(g: nx.DiGraph, vuln_nodes: set, per_node: int = 2) -> list[list[str]]:
    paths = []
    for v in sorted(vuln_nodes):
        if v not in g or not nx.has_path(g, ROOT, v):
            continue
        found = []
        for p in nx.all_simple_paths(g, ROOT, v, cutoff=nx.shortest_path_length(g, ROOT, v) + 1):
            found.append(p)
            if len(found) >= 25:
                break
        paths += sorted(found, key=len)[:per_node]
    return paths


def to_dot(g: nx.DiGraph, vuln_nodes: set, show_all_direct: bool = True, per_node: int = 1, bg: str = "transparent") -> str:
    paths = vuln_paths(g, vuln_nodes, per_node)
    on_path = {n for p in paths for n in p}
    hot_edges = {(a, b) for p in paths for a, b in zip(p, p[1:])}
    depth = nx.single_source_shortest_path_length(g, ROOT)
    nodes = set(on_path) | ({ROOT} | set(g.successors(ROOT)) if show_all_direct else set())
    lines = ['digraph V {', 'layout=twopi; root="ROOT"; ranksep="1.6 1.25 1.1 1.0"; overlap=false; splines=true;',
             f'bgcolor="{bg}"; outputorder=edgesfirst;',
             'node [shape=circle, style=filled, fontname="Helvetica", fontsize=9, penwidth=0, fixedsize=true];',
             'edge [arrowsize=0.5];']
    for n in nodes:
        d = g.nodes[n]
        label, k = d["label"], depth.get(n, 9)
        if n == ROOT:
            lines.append(f'"{n}" [label="{d["name"]}", width=1.35, fillcolor="{INK}", fontcolor="white", fontsize=12];')
            continue
        vuln = n in vuln_nodes
        color = RED if vuln else BLUE if k == 1 else LEVEL.get(min(k, 4), LEVEL[4])
        if n in on_path:
            name, _, version = label.rpartition("@")
            parts = name.split("/") if len(name) > 13 and "/" in name else [name]
            if len(parts) == 1 and len(name) > 13 and "-" in name:
                cut = name.rfind("-", 0, len(name) // 2 + 3)
                parts = [name[:cut + 1], name[cut + 1:]]
            parts = [x + ("/" if i < len(parts) - 1 and not x.endswith("-") else "") for i, x in enumerate(parts)]
            text = "\\n".join(parts + ["@" + version])
            size = max(0.95 if vuln else 0.8, 0.075 * max(len(x) for x in parts + [version]) + 0.25)
            fc = "white" if (vuln or k <= 2) else INK
            lines.append(f'"{n}" [label="{text}", width={size}, fillcolor="{color}", fontcolor="{fc}", '
                         f'tooltip="{label}"' + (f', penwidth=2.5, color="{ORANGE}"' if not vuln else "") + '];')
        else:
            lines.append(f'"{n}" [label="", width=0.16, fillcolor="{color}", tooltip="{label}"];')
    for a, b in g.edges():
        if a in nodes and b in nodes:
            if (a, b) in hot_edges:
                lines.append(f'"{a}" -> "{b}" [color="{ORANGE}", penwidth=2.2];')
            elif a == ROOT:
                lines.append(f'"{a}" -> "{b}" [color="#C9D3DC", penwidth=0.6, arrowsize=0.3];')
    return "\n".join(lines + ["}"])


def render(dot: str, out_file: Path, fmt: str = "svg", dpi: int = 160) -> bool:
    twopi = shutil.which("twopi") or shutil.which("dot")
    if not twopi:
        return False
    cmd = [twopi, f"-T{fmt}", "-o", str(out_file)] + ([f"-Gdpi={dpi}"] if fmt == "png" else [])
    if Path(twopi).name == "dot":
        cmd.insert(1, "-Ktwopi")
    proc = subprocess.run(cmd, input=dot, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.returncode == 0


# ---------- dependency-free radial layout (shared by the SVG and the PDF) ----------
def radial_layout(g: nx.DiGraph, vuln_nodes: set, per_node: int = 1) -> dict:
    import math
    paths = vuln_paths(g, vuln_nodes, per_node)
    on_path = {n for p in paths for n in p}
    hot = {(a, b) for p in paths for a, b in zip(p, p[1:])}
    depth = nx.single_source_shortest_path_length(g, ROOT)
    parent = {}
    for p in sorted(paths, key=len):
        for a, b in zip(p, p[1:]):
            parent.setdefault(b, a)
    for d in g.successors(ROOT):
        parent.setdefault(d, ROOT)
    kids = {}
    for c, par in parent.items():
        kids.setdefault(par, []).append(c)
    level, stack = {ROOT: 0}, [ROOT]
    while stack:
        n = stack.pop()
        for c in kids.get(n, []):
            level[c] = level[n] + 1
            stack.append(c)

    def weight(n):
        ch = kids.get(n, [])
        return sum(weight(c) for c in ch) if ch else (1.0 if n in on_path else 0.28)

    def radius(k):
        return 0 if k == 0 else 300 + 128 * (k - 1)
    pos = {ROOT: (0.0, 0.0)}

    def place(n, a0, a1):
        ch = sorted(kids.get(n, []), key=lambda c: g.nodes[c]["label"])
        labelled = [c for c in ch if c in on_path]
        dots = [c for c in ch if c not in on_path]
        mixed, step = [], max(1, len(dots) // max(1, len(labelled) + 1))
        for i, c in enumerate(labelled):
            mixed += dots[i * step:(i + 1) * step] + [c]
        mixed += dots[len(labelled) * step:]
        total = sum(weight(c) for c in mixed) or 1
        a = a0
        for c in mixed:
            span = (a1 - a0) * weight(c) / total
            mid = a + span / 2
            r = radius(level[c])
            pos[c] = (r * math.cos(mid), r * math.sin(mid))
            place(c, a, a + span)
            a += span
    place(ROOT, -math.pi / 2, 3 * math.pi / 2)
    sizes = {n: (58 if n == ROOT else (24 if n in vuln_nodes else 19) if n in on_path else 6) for n in pos}
    fills = {}
    for n in pos:
        k = depth.get(n, 9)
        fills[n] = INK if n == ROOT else RED if n in vuln_nodes else BLUE if k == 1 else LEVEL.get(min(k, 4), LEVEL[4])
    return {"pos": pos, "sizes": sizes, "fills": fills, "parent": parent, "hot": hot, "on_path": on_path,
            "vuln": set(vuln_nodes), "label": {n: g.nodes[n]["label"] for n in pos}, "root_name": g.nodes[ROOT]["name"]}


def label_anchor(x: float, y: float, r: float):
    import math
    ang = math.atan2(y, x)
    tx, ty = x + math.cos(ang) * (r + 8), y + math.sin(ang) * (r + 8)
    anchor = "start" if math.cos(ang) > 0.25 else "end" if math.cos(ang) < -0.25 else "middle"
    ty += 6 if math.sin(ang) > 0.6 else -14 if math.sin(ang) < -0.6 else -4
    return tx, ty, anchor


def radial_svg(g: nx.DiGraph, vuln_nodes: set, per_node: int = 1, dark: bool = False) -> str:
    import math
    from html import escape
    L = radial_layout(g, vuln_nodes, per_node)
    pos, sizes, fills, hot = L["pos"], L["sizes"], L["fills"], L["hot"]
    bg, ink, quiet, wire = ("#0E1A26", "#E6EDF3", "#9FB0C2", "#2B3D52") if dark else ("#FFFFFF", INK, STEEL, "#C9D3DC")
    root_fill = "#2F6FBF" if dark else INK
    xs = [x for x, _ in pos.values()]
    ys = [y for _, y in pos.values()]
    pad = 250
    minx, maxx, miny, maxy = min(xs) - pad, max(xs) + pad, min(ys) - pad, max(ys) + pad
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{minx:.0f} {miny:.0f} {maxx - minx:.0f} {maxy - miny:.0f}" '
           f'font-family="Archivo, Segoe UI, Helvetica, Arial, sans-serif" style="width:100%;height:auto;background:{bg}">',
           f'<rect x="{minx:.0f}" y="{miny:.0f}" width="{maxx - minx:.0f}" height="{maxy - miny:.0f}" fill="{bg}"/>',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           f'<path d="M0,0 L10,5 L0,10 z" fill="{ORANGE}"/></marker></defs>']
    for c, par in L["parent"].items():
        if c in pos and par in pos and (par, c) not in hot:
            (x1, y1), (x2, y2) = pos[par], pos[c]
            out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{wire}" stroke-width="1"/>')
    for a, b in hot:
        if a in pos and b in pos:
            (x1, y1), (x2, y2) = pos[a], pos[b]
            dx, dy = x2 - x1, y2 - y1
            dist = math.hypot(dx, dy) or 1
            ex, ey = x2 - dx / dist * (sizes[b] + 3), y2 - dy / dist * (sizes[b] + 3)
            out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="{ORANGE}" '
                       f'stroke-width="3" marker-end="url(#arr)"/>')
    for n, (x, y) in pos.items():
        r = sizes[n]
        if n == ROOT:
            out.append(f'<circle cx="0" cy="0" r="{r}" fill="{root_fill}"/><text x="0" y="6" text-anchor="middle" '
                       f'font-size="19" font-weight="700" fill="#FFFFFF">{escape(L["root_name"])}</text>')
            continue
        ring = f' stroke="{ORANGE}" stroke-width="3"' if (n in L["on_path"] and n not in L["vuln"]) else ""
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{fills[n]}"{ring}><title>{escape(L["label"][n])}</title></circle>')
        if n in L["on_path"]:
            name, _, ver = L["label"][n].rpartition("@")
            tx, ty, anchor = label_anchor(x, y, r)
            weight_attr = ' font-weight="700"' if n in L["vuln"] else ""
            out.append(f'<text x="{tx:.1f}" y="{ty:.1f}" text-anchor="{anchor}" font-size="17" fill="{ink}"{weight_attr}>'
                       f'{escape(name)}<tspan x="{tx:.1f}" dy="18" font-size="14" fill="{quiet}">@{escape(ver)}</tspan></text>')
    out.append("</svg>")
    return "\n".join(out)
