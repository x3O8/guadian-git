"""Self-contained HTML dependency explorer (npm-ls style collapsible tree)."""
import json
from pathlib import Path

import networkx as nx

ROOT = "ROOT"


def tree_data(g: nx.DiGraph, vulnerable: set) -> dict:
    ids = [ROOT] + sorted((n for n in g.nodes if n != ROOT), key=lambda n: g.nodes[n]["label"])
    idx = {n: i for i, n in enumerate(ids)}
    leads_to_vuln = set()
    for v in vulnerable:
        if v in g:
            leads_to_vuln |= nx.ancestors(g, v)
    depth = nx.single_source_shortest_path_length(g, ROOT)
    parent = {child: par for par, child in nx.bfs_edges(g, ROOT)}
    nodes = []
    for n in ids:
        d = g.nodes[n]
        nodes.append({"l": d["label"], "s": d.get("scope", ""), "d": bool(d.get("direct")),
                      "v": n in vulnerable, "w": n in leads_to_vuln, "k": depth.get(n, -1),
                      "p": idx[parent[n]] if n in parent else -1,
                      "n": len(nx.descendants(g, n)) if (n == ROOT or d.get("direct")) else None})
    children = []
    for n in ids:
        kids = sorted(g.successors(n), key=lambda c: (c not in vulnerable and c not in leads_to_vuln,
                                                      g.nodes[c]["label"]))
        children.append([idx[c] for c in kids])
    return {"nodes": nodes, "children": children}


DARK_CSS = """
 body{background:#0E1A26;color:#E6EDF3}
 input,button{background:#16263A;color:#E6EDF3;border-color:#2B3D52} button:hover{background:#1E3249}
 .stats,.legend span,.muted,.tog{color:#9FB0C2} .why{background:#16263A;border-left-color:#5B9BE6}
 .why .chain code{background:#1E3249;color:#E6EDF3} ul{border-left-color:#2B3D52}
 .row.hit{background:#3A2E10;outline-color:#E3B341} .direct .pkg{color:#8DBBF3} .vuln .pkg{color:#F48A80}
 .tag{border-color:#2B3D52;color:#9FB0C2} .tag.blue{background:#1A3352;border-color:#24466F;color:#A9CBF6}
 .tag.orange{background:#3D2616;border-color:#6B3F1F;color:#F2B08A} .tag.red{background:#C2362B;border-color:#C2362B}
"""


def tree_html(g: nx.DiGraph, vulnerable: set = frozenset(), dark: bool = False) -> str:
    data = json.dumps(tree_data(g, set(vulnerable)), separators=(",", ":")).replace("</", "<\\/")
    html = TEMPLATE.replace("__DATA__", data)
    return html.replace("</style>", DARK_CSS + "</style>") if dark else html


def render_tree(g: nx.DiGraph, out_file: Path, vulnerable: set = frozenset()) -> Path:
    out_file.write_text(tree_html(g, vulnerable), encoding="utf-8")
    return out_file


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Dependency explorer</title>
<style>
 body{font-family:Archivo,'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;margin:12px 4px;color:#1B2A3A;font-size:14px;background:#F4F6F7}
 .bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
 input{padding:7px 10px;border:1px solid #D3DBE2;border-radius:4px;min-width:280px;font-size:14px;font-family:inherit}
 button{padding:7px 12px;border:1px solid #D3DBE2;background:#fff;border-radius:4px;cursor:pointer;font-size:13px;font-family:inherit;color:#1B2A3A}
 button:hover{background:#E8EDF1}button:focus-visible,input:focus-visible{outline:2px solid #1F5FAE;outline-offset:1px}
 .stats{color:#5E6E7E;margin:4px 0 8px;max-width:80ch}
 .legend span{margin-right:16px;font-size:12px;color:#5E6E7E}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
 .why{background:#fff;border-left:3px solid #1F5FAE;border-radius:2px;padding:10px 12px;margin:10px 0;display:none}
 .why .chain code{background:#E8EDF1;border-radius:6px;padding:2px 6px;margin:2px}
 .matches button{margin:2px 4px 2px 0;font-size:12px;padding:4px 8px}
 ul{list-style:none;margin:0;padding-left:20px;border-left:1px solid #D3DBE2}
 #tree>ul{border-left:none;padding-left:0}
 li{margin:2px 0;white-space:nowrap}
 .row{display:inline-flex;align-items:center;gap:6px;padding:2px 6px;border-radius:6px}
 .row.hit{background:#FFF4D6;outline:2px solid #C98A00}
 .tog{width:18px;display:inline-block;text-align:center;cursor:pointer;color:#5E6E7E;user-select:none}
 .pkg{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;font-size:13px;cursor:pointer}
 .root .pkg{font-weight:700}
 .direct .pkg{color:#1F5FAE;font-weight:600}
 .vuln .pkg{color:#B3261E;font-weight:700}
 .tag{font-size:11px;border-radius:3px;padding:1px 6px;border:1px solid #D3DBE2;color:#5E6E7E}
 .tag.red{background:#B3261E;border-color:#B3261E;color:#fff}
 .tag.orange{background:#FBE5D6;border-color:#F2C2A2;color:#9A3F12}
 .tag.blue{background:#E1EBF7;border-color:#C3D5EE;color:#1F5FAE}
 .muted{color:#8593A0;font-size:12px}
</style></head><body>
<div class="bar">
 <input id="q" list="pkgs" placeholder="Find a package, e.g. lodash" autocomplete="off">
 <datalist id="pkgs"></datalist>
 <button id="go">Why is it here?</button>
 <button id="vuln">Show every route to an advisory</button>
 <button id="collapse">Collapse all</button>
</div>
<div class="stats" id="stats"></div>
<div class="legend"><span><i style="background:#1F5FAE"></i>listed in package.json</span><span><i style="background:#5E6E7E"></i>pulled in by another package</span>
<span><i style="background:#B3261E"></i>has advisories</span><span><i style="background:#F2C2A2"></i>leads to a package with advisories</span></div>
<div class="why" id="why"></div>
<div id="tree"></div>
<script>
const D = __DATA__, N = D.nodes, C = D.children;
const $ = id => document.getElementById(id);
const depthMax = Math.max(...N.map(n => n.k));
const vulnCount = N.filter(n => n.v).length, direct = C[0].length;
$("stats").textContent = `${N[0].l} uses ${direct} direct dependencies, which pull in ${N.length - 1 - direct} more ` +
  `(transitive) packages, up to ${depthMax} levels deep. ${vulnCount} installed packages have known vulnerabilities.`;
const dl = $("pkgs"); N.slice(1).forEach(n => { const o = document.createElement("option"); o.value = n.l; dl.appendChild(o); });

function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }

function makeLi(i, ancestors) {
  const n = N[i], li = el("li"); li.dataset.idx = i;
  const row = el("span", "row" + (i === 0 ? " root" : n.v ? " vuln" : n.d ? " direct" : ""));
  const tog = el("span", "tog", C[i].length ? "▸" : "·");
  row.append(tog, el("span", "pkg", n.l));
  if (i !== 0 && n.d) row.append(el("span", "tag blue", "in package.json"));
  if (n.s === "dev") row.append(el("span", "tag", "dev only"));
  if (n.v) row.append(el("span", "tag red", "advisories"));
  else if (n.w) row.append(el("span", "tag orange", "leads to advisories"));
  if (n.n != null && i !== 0) row.append(el("span", "muted", `brings in ${n.n} packages`));
  else if (C[i].length) row.append(el("span", "muted", `${C[i].length} deps`));
  li.append(row);
  li._anc = ancestors;
  tog.onclick = () => toggle(li);
  row.querySelector(".pkg").onclick = () => toggle(li);
  return li;
}

function expand(li) {
  const i = +li.dataset.idx; if (!C[i].length || li._open) return li.querySelector(":scope > ul");
  const anc = new Set(li._anc); anc.add(i);
  const ul = el("ul");
  C[i].forEach(c => {
    if (anc.has(c)) { const x = el("li", "muted", `↺ ${N[c].l} (circular)`); ul.append(x); }
    else ul.append(makeLi(c, anc));
  });
  li.append(ul); li._open = true; li.querySelector(".tog").textContent = "▾"; return ul;
}
function collapse(li) { const ul = li.querySelector(":scope > ul"); if (ul) ul.remove(); li._open = false;
  const t = li.querySelector(".tog"); if (C[+li.dataset.idx].length) t.textContent = "▸"; }
function toggle(li) { li._open ? collapse(li) : expand(li); }

function pathTo(i) { const p = []; while (i !== -1) { p.unshift(i); i = N[i].p; } return p; }
function reveal(path) {
  let li = rootLi;
  for (const i of path.slice(1)) {
    const ul = expand(li);
    li = [...ul.children].find(x => +x.dataset.idx === i);
    if (!li) return null;
  }
  return li;
}
function explain(i) {
  const p = pathTo(i), n = N[i], box = $("why");
  box.style.display = "block"; box.innerHTML = "";
  const head = el("div"); head.innerHTML = "<b>Why is <code></code> here?</b>"; head.querySelector("code").textContent = n.l;
  const chain = el("div", "chain"); p.forEach((j, k) => { if (k) chain.append(" → "); chain.append(el("code", "", N[j].l)); });
  let msg;
  if (i === 0) msg = "This is the application itself.";
  else if (n.d) msg = "It is a direct dependency: the project lists it in package.json.";
  else msg = `It is a transitive dependency: the project never asked for it directly. It arrives through the ` +
             `direct dependency ${N[p[1]].l}, ${p.length - 1} levels deep.`;
  if (n.v) msg += " It has known vulnerabilities — see the Vulnerabilities tab.";
  if (n.s === "dev") msg += " It is only used during development, not shipped.";
  box.append(head, chain, el("div", "", msg));
}
function focus(i) {
  document.querySelectorAll(".row.hit").forEach(r => r.classList.remove("hit"));
  collapse(rootLi); expand(rootLi);
  const li = reveal(pathTo(i));
  if (li) { const r = li.querySelector(".row"); r.classList.add("hit"); r.scrollIntoView({block: "center"}); }
  explain(i);
}
function search() {
  const q = $("q").value.trim().toLowerCase(); if (!q) return;
  const hits = N.map((n, i) => [n, i]).filter(([n]) => n.l.toLowerCase().includes(q));
  const exact = hits.find(([n]) => n.l.toLowerCase() === q || n.l.toLowerCase().startsWith(q + "@"));
  if (!hits.length) { $("why").style.display = "block"; $("why").textContent = `No installed package matches "${q}".`; return; }
  focus((exact || hits[0])[1]);
  if (hits.length > 1) {
    const m = el("div", "matches"); m.append(el("span", "muted", `${hits.length} matches: `));
    hits.slice(0, 15).forEach(([n, i]) => { const b = el("button", "", n.l); b.onclick = () => focus(i); m.append(b); });
    $("why").append(m);
  }
}
$("go").onclick = search;
$("q").addEventListener("keydown", e => { if (e.key === "Enter") search(); });
$("collapse").onclick = () => { collapse(rootLi); expand(rootLi); $("why").style.display = "none"; };
$("vuln").onclick = () => {
  collapse(rootLi); expand(rootLi);
  N.forEach((n, i) => { if (n.v && n.p !== -1) { const li = reveal(pathTo(i)); if (li) li.querySelector(".row").classList.add("hit"); } });
  $("why").style.display = "block";
  $("why").textContent = vulnCount ? `Expanded the shortest path to each of the ${vulnCount} vulnerable packages (highlighted).`
                                   : "No vulnerable packages.";
};
const treeUl = el("ul"), rootLi = makeLi(0, new Set()); treeUl.append(rootLi); $("tree").append(treeUl); expand(rootLi);
</script></body></html>
"""
