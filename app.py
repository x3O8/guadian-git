import hashlib
import io
import json
import re
import subprocess
import zipfile
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

import altair as alt
import networkx as nx
import pandas as pd
import streamlit as st

from guardian import analysis, ui_day2, vuln_graph
from guardian.repo_fetch import FetchError, fetch, out_dir_for
from guardian.tree_html import tree_html
from guardian.workflow import run_stream

ROOT = Path(__file__).parent
TARGETS = ROOT / "target"

# dark palette
BG, SURFACE, LINE, TEXT, MUTED = "#0E1A26", "#16263A", "#2B3D52", "#E6EDF3", "#9FB0C2"
BLUE, RED, ORANGE, AMBER, GREEN = "#5B9BE6", "#F0645A", "#F08A4B", "#E3B341", "#4CC38A"
SEV_COLOR = {"critical": RED, "high": ORANGE, "moderate": AMBER, "medium": AMBER, "low": BLUE, "info": MUTED, "unknown": MUTED}
GRADE_COLOR = {"A": GREEN, "B": GREEN, "C": AMBER, "D": ORANGE, "F": RED}
AGENTS = ["1. Repository Discovery Agent", "2. SBOM Agent", "3. Dependency Analysis Agent",
          "4. Vulnerability Detection Agent", "5. Anomaly Detection Agent"]
CHECKS = [("unexpected_dependency", "Unexpected dependency"), ("suspicious_package_name", "Typosquatted (look-alike) name"),
          ("suspicious_version_change", "Suspicious version change"), ("lifecycle_script", "Unsafe install script"),
          ("unpinned_container_image", "Untrusted or unpinned image"), ("lockfile_modified", "Modified lockfile"),
          ("unexpected_ci_dependency", "Unexpected CI/CD dependency")]

st.set_page_config(page_title="Guardian · supply chain inspection", page_icon="🛡️", layout="wide")
st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,400..800&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, .stApp, .stMarkdown p, .stMarkdown li, label, input, textarea, [data-testid="stMarkdownContainer"] p {{
  font-family: 'Archivo', 'Segoe UI', system-ui, -apple-system, Helvetica, Arial, sans-serif; }}
h1, h2, h3 {{ font-family: 'Archivo', 'Segoe UI', sans-serif !important; font-stretch: 82%; color: {TEXT}; letter-spacing: -0.005em; }}
h1 {{ font-weight: 800 !important; font-size: 2.5rem !important; line-height: 1.05 !important; padding: 0 !important; }}
h2 {{ font-weight: 750 !important; font-size: 1.55rem !important; }}
h3 {{ font-weight: 700 !important; font-size: 1.12rem !important; }}
code {{ font-family: 'JetBrains Mono', Consolas, monospace !important; font-size: .84em; color: {TEXT} !important;
        background: #1E3249 !important; border-radius: 3px; padding: 1px 5px; }}
.block-container {{ padding-top: 2rem; max-width: 1320px; }}
[data-testid="stSidebar"] {{ background: #0B1520; border-right: 1px solid {LINE}; }}
.stButton > button, .stDownloadButton > button {{ border-radius: 4px; font-weight: 600; }}
.stMarkdown p.wordmark {{ font-stretch: 70%; font-weight: 800; font-size: 2.1rem !important; line-height: 1 !important; color: {TEXT}; margin: 0 0 .2rem !important; }}
.stMarkdown p.wordmark-sub {{ color: {MUTED}; font-size: .88rem !important; margin: 0 0 1rem !important; }}
.kicker {{ color: {MUTED}; font-size: .92rem; margin-bottom: .1rem; }}
.manifest {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); border-top: 3px solid {TEXT};
            border-bottom: 1px solid {LINE}; margin: .6rem 0 1.4rem; }}
.manifest > div {{ padding: .7rem 1rem .8rem 0; border-right: 1px solid {LINE}; margin-right: 1rem; }}
.manifest > div:last-child {{ border-right: none; }}
.manifest .k {{ color: {MUTED}; font-size: .8rem; }}
.manifest .v {{ font-size: 1.45rem; font-weight: 700; font-stretch: 82%; margin-top: .15rem; color: {TEXT}; }}
.manifest .v small {{ display: block; font-size: .78rem; font-weight: 500; color: {MUTED}; font-stretch: 100%; line-height: 1.3; }}
.stamp {{ --c: {RED}; display: inline-flex; align-items: center; gap: .9rem; color: var(--c); border: 4px solid var(--c);
         border-radius: 8px; padding: .55rem 1.2rem .55rem .9rem; box-shadow: inset 0 0 0 3px {BG}, inset 0 0 0 5px var(--c);
         transform: rotate(-3.5deg); margin: .4rem 0 1.2rem; animation: thump .45s cubic-bezier(.2,1.6,.4,1) 1; }}
.stamp .grade {{ font-size: 4.2rem; font-weight: 800; font-stretch: 62%; line-height: .9; }}
.stamp .verdict {{ font-size: 1.15rem; font-weight: 800; font-stretch: 70%; text-transform: uppercase; letter-spacing: .08em; line-height: 1.1; }}
.stamp .verdict span {{ display: block; font-size: .72rem; letter-spacing: .04em; font-weight: 600; opacity: .85; }}
@keyframes thump {{ from {{ transform: rotate(-3.5deg) scale(1.6); opacity: 0; }} to {{ transform: rotate(-3.5deg) scale(1); opacity: 1; }} }}
@media (prefers-reduced-motion: reduce) {{ .stamp {{ animation: none; }} }}
.qa {{ border: 1px solid {LINE}; border-radius: 6px; padding: .9rem 1rem; background: {SURFACE}; height: 100%; }}
.qa .q {{ font-weight: 700; font-stretch: 85%; font-size: 1.08rem; margin-bottom: .35rem; color: {TEXT}; }}
.qa .a {{ color: {TEXT}; line-height: 1.5; font-size: .95rem; }}
.qa .go {{ color: {MUTED}; font-size: .82rem; margin-top: .5rem; }}
.list {{ list-style: none; padding: 0; margin: 0; }}
.list li {{ display: grid; grid-template-columns: 5.2rem 1fr; gap: .8rem; padding: .62rem 0; border-bottom: 1px solid {LINE}; line-height: 1.45; }}
.list .fix {{ color: {GREEN}; font-size: .9rem; margin-top: .2rem; }}
.sev {{ font-size: .76rem; font-weight: 700; padding: .12rem .5rem; border-radius: 3px; color: #0E1A26; justify-self: start; align-self: start; margin-top: .12rem; }}
.note {{ color: {MUTED}; font-size: .9rem; }}
.lead {{ font-size: 1.04rem; line-height: 1.55; max-width: 78ch; color: {TEXT}; }}
.swatch {{ display: inline-block; width: .75rem; height: .75rem; border-radius: 2px; margin: 0 .3rem 0 .9rem; vertical-align: -1px; }}
.cover {{ display: grid; grid-template-columns: 2.2rem 1fr auto; gap: .7rem; padding: .55rem 0; border-bottom: 1px solid {LINE}; align-items: center; }}
.cover .ok {{ color: {GREEN}; font-weight: 800; font-size: 1.1rem; }}
.cover .bad {{ color: {RED}; font-weight: 800; font-size: 1.1rem; }}
.cover .ev {{ color: {MUTED}; font-size: .88rem; }}
</style>""", unsafe_allow_html=True)


def _theme():
    return {"config": {
        "background": "transparent", "font": "Archivo, Segoe UI, Helvetica, Arial, sans-serif", "view": {"stroke": None},
        "axis": {"labelColor": MUTED, "titleColor": MUTED, "gridColor": "#22344A", "domainColor": LINE, "tickColor": LINE,
                 "labelFontSize": 11.5, "titleFontSize": 11.5},
        "legend": {"labelColor": MUTED, "titleColor": MUTED, "labelFontSize": 11.5},
        "title": {"color": TEXT}}}


if hasattr(alt, "theme") and hasattr(alt.theme, "register"):
    alt.theme.register("guardian_dark", enable=True)(_theme)
else:
    alt.themes.register("guardian_dark", _theme)
    alt.themes.enable("guardian_dark")


# ---------------- helpers ----------------
def load(out: Path, name: str):
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def list_repos() -> list[Path]:
    return sorted(p for p in TARGETS.iterdir() if (p / "package.json").exists()) if TARGETS.exists() else []


def recent_commits(repo: Path, limit: int = 200):
    proc = subprocess.run(["git", "-C", str(repo), "log", f"-n{limit}", "--date=short", "--format=%h|%ad|%s"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    rows = []
    for k, line in enumerate(proc.stdout.splitlines()):
        sha, date, subject = (line.split("|", 2) + ["", ""])[:3]
        rows.append(("Latest commit (uncommitted changes only)" if k == 0 else f"{k} commits back, {date}: {subject[:55]}",
                     "HEAD" if k == 0 else sha))
    return rows or [("Latest commit (uncommitted changes only)", "HEAD")]


def when(iso):
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return iso or "—"


def mono(x) -> str:
    return f"<code>{escape(str(x))}</code>"


def sev_badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOR.get(sev, MUTED)}">{escape(sev)}</span>'


def show_html(html: str, height: int):
    if hasattr(st, "iframe"):
        st.iframe(html, height=height)
    else:
        import streamlit.components.v1 as components
        components.html(html, height=height, scrolling=True)


def section(title: str, lead: str):
    st.markdown(f"## {title}")
    st.markdown(f'<p class="lead">{lead}</p>', unsafe_allow_html=True)


def bar(df, x, y, color=BLUE, height=260, sort="-x", color_enc=None):
    return alt.Chart(df).mark_bar(cornerRadiusEnd=2).encode(
        x=alt.X(f"{x}:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
        y=alt.Y(f"{y}:N", sort=sort, title=None, axis=alt.Axis(labelOverlap=False, labelLimit=280)),
        color=color_enc if color_enc is not None else alt.value(color), tooltip=list(df.columns)).properties(height=height)


@st.cache_data
def load_graph(path: str, mtime: float):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    g = nx.DiGraph()
    for n in data["nodes"]:
        g.add_node(n["id"], **{k: n[k] for k in ("label", "name", "version", "direct", "scope")})
    g.add_edges_from((e["from"], e["to"]) for e in data["edges"])
    return g, {n["id"]: n for n in data["nodes"]}


@st.cache_data
def graph_stats(path: str, mtime: float):
    g, _ = load_graph(path, mtime)
    return nx.single_source_shortest_path_length(g, "ROOT"), {n: len(nx.descendants(g, n)) for n in g.successors("ROOT")}


def paths_dot(g, paths, target, vulnerable):
    keep = {n for p in paths for n in p}
    lines = ['digraph G { rankdir=LR; nodesep=0.25; bgcolor="transparent"; node [shape=box, style="rounded,filled", '
             'fontname="Helvetica", fontsize=11, fontcolor=white, penwidth=0];']
    for n in keep:
        d = g.nodes[n]
        c = "#2F6FBF" if n == "ROOT" else "#C2362B" if n == target else "#C8642F" if d["label"] in vulnerable \
            else "#2E5E9E" if d.get("direct") else "#3A4E66"
        lines.append(f'"{n}" [label="{d["label"]}", fillcolor="{c}"];')
    lines += [f'"{a}" -> "{b}" [color="{MUTED}"];' for a, b in {(a, b) for p in paths for a, b in zip(p, p[1:])}]
    return "\n".join(lines + ["}"])


def pipeline_dot(log):
    status = {e["agent"]: e["status"] for e in log}
    fill = {"ok": "#2E8B62", "error": "#C2362B", "skipped": "#3A4E66"}
    nodes = ["start"] + AGENTS + ["report", "end"]
    lines = ['digraph P { rankdir=LR; bgcolor="transparent"; node [shape=box, style="rounded,filled", fontname="Helvetica", '
             'fontsize=11, fontcolor=white, penwidth=0];']
    for n in nodes:
        key = next((k for k in status if k.startswith(n) or (n == "report" and k.startswith("Report"))), None)
        lines.append(f'"{n}" [fillcolor="{"#2F6FBF" if n in ("start", "end") else fill.get(status.get(key), "#3A4E66")}"];')
    lines += [f'"{a}" -> "{b}" [color="{MUTED}"];' for a, b in zip(nodes, nodes[1:])]
    return "\n".join(lines + ["}"])


def scan(repo: Path, base_ref: str, scanner: str, status) -> bool:
    status.write(f"Inspecting **{repo.name}** with 5 agents")
    final = None
    for kind, item in run_stream(str(repo), str(out_dir_for(repo)), base_ref, scanner):
        if kind == "log":
            status.write(f"**{item.agent}** — {dict(ok='done', error='failed', skipped='skipped').get(item.status, item.status)}. {item.message}")
        else:
            final = item
    st.cache_data.clear()
    if final and final.get("errors"):
        status.update(label="Inspection finished with errors", state="error", expanded=True)
        return False
    status.update(label=f"Inspection complete: {repo.name}", state="complete", expanded=False)
    return True


# ---------------- sidebar ----------------
st.sidebar.markdown('<p class="wordmark">Guardian</p><p class="wordmark-sub">Software supply chain inspection</p>',
                    unsafe_allow_html=True)
with st.sidebar.expander("Add a repository from GitHub", expanded=not list_repos()):
    url = st.text_input("Public repository link", placeholder="https://github.com/owner/repo")
    refresh = st.checkbox("Download a fresh copy if it's already here")
    fetch_clicked = st.button("Fetch and inspect", type="primary", width="stretch", disabled=not url.strip())
    st.caption("Node.js projects only. Nothing from the repository is run on your machine.")
if fetch_clicked:
    with st.status(f"Fetching {url.strip()}", expanded=True) as status:
        dest = None
        try:
            dest = fetch(url, refresh, log=status.write)
        except FetchError as err:
            status.update(label="This repository can't be inspected", state="error", expanded=True)
            st.error(str(err))
        except Exception as err:
            status.update(label="Fetching stopped unexpectedly", state="error", expanded=True)
            st.error(f"{type(err).__name__}: {err}")
        if dest is not None:
            from guardian import publishing
            try:
                source = publishing.git(dest, "remote", "get-url", "origin")
                publishing.git(dest, "config", "--local", "guardian.source", source)
                destination_url = publishing.destination(dest, source)
                status.write(f"Fix repository: {destination_url}")
            except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as err:
                st.warning(f"GitHub setup pending. {err} Validation will retry publishing.")
            scan(dest, "HEAD", "auto", status)
            st.session_state["repo_choice"] = dest.name

repos = list_repos()
if not repos:
    st.markdown("# Nothing inspected yet")
    st.markdown("Paste a public GitHub link under **Add a repository from GitHub**, or run `setup.bat` to add OWASP Juice Shop.")
    st.stop()
names = [p.name for p in repos]
if st.session_state.get("repo_choice") not in names:
    st.session_state["repo_choice"] = "juice-shop" if "juice-shop" in names else names[0]
repo = TARGETS / st.sidebar.selectbox("Repository", names, key="repo_choice")
with st.sidebar.expander("Inspection settings"):
    commits = recent_commits(repo)
    base_label = st.selectbox("Compare changes against", [c[0] for c in commits], index=0,
                              help="Step 4 lists what changed in package.json, the lockfile, Dockerfiles and CI since this commit.")
    base_ref = dict(commits)[base_label]
    scanner = st.selectbox("Vulnerability source", ["auto", "osv", "npm-audit"],
                           format_func={"auto": "OSV, falling back to npm audit", "osv": "OSV only", "npm-audit": "npm audit only"}.get)
if st.sidebar.button("Inspect again", width="stretch"):
    with st.status(f"Inspecting {repo.name}", expanded=True) as status:
        scan(repo, base_ref, scanner, status)

# ---------------- data ----------------
out = out_dir_for(repo)
report = load(out, "evidence_report.json")
if not report:
    st.markdown(f"# {repo.name}")
    st.markdown("This repository hasn't been inspected yet. Choose **Inspect again** in the sidebar.")
    st.stop()
inventory, deps_doc = load(out, "inventory.json"), load(out, "dependency_inventory.json") or {"dependencies": []}
vulns = load(out, "vulnerability_findings.json") or {"findings": [], "scanner": None}
susp = load(out, "suspicious_changes.json") or {"findings": [], "base_ref": "HEAD", "notes": []}
recs = load(out, "fix_recommendations.json") or []
findings, deps = vulns["findings"], deps_doc["dependencies"]
changes = [f for f in susp["findings"] if f["kind"] == "change"]
posture = [f for f in susp["findings"] if f["kind"] == "baseline"]
m, sev, inv_s = report["metrics"], report["metrics"]["vulnerabilities_by_severity"], inventory["summary"]
vdf, ddf = pd.DataFrame(findings), pd.DataFrame(deps)
gpath = out / "dependency_graph.json"
pdf_path = out / "evidence_report.pdf"
vuln_pkgs = len({(f["package"], f["installed_version"]) for f in findings})

# ---------------- navigation (grouped: Day 1, Day 2, Evaluate) ----------------
def p_overview(): overview()
def p_components(): components_page()
def p_supply(): supply_chain_page()
def p_vulns(): vulnerabilities_page()
def p_changes(): changes_page()
def p_evidence(): evidence_page()
def p_day2(): ui_day2.mission(repo, out)
def p_risks(): ui_day2.risks_page(repo, out)
def p_investigate(): ui_day2.investigate_page(repo, out)
def p_approve(): ui_day2.approval_page(repo, out)
def p_validate(): ui_day2.validation_page(repo, out)
def p_journey(): ui_day2.journey_page(repo, out)
def p_report2(): ui_day2.report_page(repo, out)
def p_compare(): compare_page()
def p_bench(): ui_day2.benchmark_page(ROOT)


nav = st.navigation({
    "Day 1 · See what's inside": [
        st.Page(p_overview, title="Overview", url_path="overview", default=True),
        st.Page(p_components, title="1 · Components", url_path="components"),
        st.Page(p_supply, title="2 · Supply chain view", url_path="supply-chain"),
        st.Page(p_vulns, title="3 · Vulnerabilities", url_path="vulnerabilities"),
        st.Page(p_changes, title="4 · Suspicious changes", url_path="changes"),
        st.Page(p_evidence, title="5 · Evidence & report", url_path="evidence")],
    "Day 2 · Act on it": [
        st.Page(p_day2, title="Day 2 overview", url_path="day2"),
        st.Page(p_risks, title="6 · Risk priorities", url_path="risks"),
        st.Page(p_investigate, title="6 · Suspicious changes", url_path="investigate"),
        st.Page(p_approve, title="7 · Remediation & approval", url_path="approve"),
        st.Page(p_validate, title="8 · Validation", url_path="validate"),
        st.Page(p_report2, title="8 · Verified report", url_path="verified-report"),
        st.Page(p_journey, title="Detection → verified fix", url_path="journey")],
    "Evaluate": [
        st.Page(p_compare, title="Compare repositories", url_path="compare"),
        st.Page(p_bench, title="Benchmark vs other tools", url_path="benchmark")],
}, expanded=True)
day2_page = nav.url_path in ("day2", "risks", "investigate", "approve", "validate", "verified-report", "journey")

# ---------------- header with the right PDF button for the section ----------------
left, right = st.columns([4.6, 1.6], vertical_alignment="bottom")
with left:
    st.markdown(f'<div class="kicker">{"Day 2 · remediation" if day2_page else "Inspection manifest"}</div>', unsafe_allow_html=True)
    st.markdown(f"# {repo.name}")
with right:
    pdf2 = out / "day2" / "verified_report.pdf"
    if day2_page and pdf2.exists():
        st.download_button("⬇  Verified report PDF", pdf2.read_bytes(), f"{repo.name}-verified-remediation.pdf",
                           "application/pdf", type="primary", width="stretch", key="pdf2_top")
    elif pdf_path.exists():
        st.download_button("⬇  Evidence report PDF", pdf_path.read_bytes(), f"{repo.name}-evidence-report.pdf",
                           "application/pdf", type="primary", width="stretch", key="pdf_top")
    elif st.button("Create evidence report (PDF)", type="primary", width="stretch"):
        try:
            from guardian.pdf_report import build_pdf
            build_pdf(out)
            st.rerun()
        except ImportError:
            st.error("Install reportlab first: pip install reportlab")
st.markdown(f"""<div class="manifest">
 <div><div class="k">Commit</div><div class="v"><code>{escape((report['commit'] or 'n/a')[:9])}</code></div></div>
 <div><div class="k">Inspected</div><div class="v"><small>{escape(when(report['generated_at']))}</small></div></div>
 <div><div class="k">Packages</div><div class="v">{m['npm_packages']}<small>{m['direct_dependencies']} chosen, {m['transitive_dependencies']} pulled in</small></div></div>
 <div><div class="k">Advisories</div><div class="v">{m['vulnerabilities']}<small>in {vuln_pkgs} packages</small></div></div>
 <div><div class="k">Critical / high</div><div class="v" style="color:{RED if sev.get('critical') else TEXT}">{sev.get('critical', 0)} / {sev.get('high', 0)}</div></div>
 <div><div class="k">Changes since <code>{escape(str(susp['base_ref'])[:9])}</code></div><div class="v">{len(changes)}</div></div>
</div>""", unsafe_allow_html=True)
if report.get("errors"):
    st.error("Some agents failed during the last inspection: " + " | ".join(report["errors"]))


# ================= pages =================
def overview():
    score, letter, verdict, breakdown = analysis.risk_grade(findings, changes, inventory)
    cp = analysis.checkpoint(report, inventory, vulns, susp)
    a, b = st.columns([4, 8], gap="large")
    with a:
        st.markdown(f'<div class="stamp" style="--c:{GRADE_COLOR[letter]}"><div class="grade">{letter}</div>'
                    f'<div class="verdict">{escape(verdict)}<span>score {score} of 100</span></div></div>', unsafe_allow_html=True)
        st.markdown(f'<p class="lead">{escape(repo.name)} ships {inv_s["npm_packages"] - inv_s["dev"]} packages to production. '
                    f'{m["vulnerable_prod"]} of {m["vulnerabilities"]} advisories affect them; '
                    f'{sum(1 for f in findings if f.get("fixed_version"))} have a fixed version.</p>', unsafe_allow_html=True)
        with st.expander("How the grade is calculated"):
            st.markdown("Start at 100 and subtract points for each real finding. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F.")
            if breakdown:
                st.dataframe(pd.DataFrame(breakdown), hide_index=True, width="stretch")
    with b:
        st.markdown("### Day 1 checkpoint")
        c = st.columns(3)
        for col, (q, key, go) in zip(c, [("What is in the application?", "inside", "Steps 1 and 2"),
                                          ("What changed?", "changed", "Step 4"), ("What appears risky?", "risky", "Steps 3 and 4")]):
            col.markdown(f'<div class="qa"><div class="q">{q}</div><div class="a">{escape(cp[key])}</div>'
                         f'<div class="go">Details: {go}</div></div>', unsafe_allow_html=True)

    st.markdown("### Fix these first")
    items = []
    for f in changes:
        if f["severity"] in ("critical", "high"):
            items.append((0, f["severity"], f"<b>{escape(f['title'])}</b> in {mono(f['file'])}.", f.get("remediation", "")))
    for r in recs:
        if r["priority"].startswith("P1"):
            via = "listed in package.json" if r["direct"] else "pulled in by " + ", ".join(mono(v) for v in r["introduced_via"][:2])
            items.append((1, r["worst_severity"], f"{mono(r['package'] + '@' + r['installed_version'])}: {r['advisories']} "
                          f"advisor{'y' if r['advisories'] == 1 else 'ies'}, {via}.", r["headline"]))
    items.sort(key=lambda x: (x[0], analysis.sev_rank(x[1])))
    if not items:
        st.markdown("Nothing critical or high. Step 3 lists the lower-severity advisories and their fixes.")
    else:
        st.markdown('<ul class="list">' + "".join(
            f'<li>{sev_badge(s)}<div>{txt}<div class="fix">Fix: {escape(fix)}</div></div></li>' for _, s, txt, fix in items[:8])
            + "</ul>", unsafe_allow_html=True)
        if len(items) > 8:
            st.caption(f"{len(items) - 8} more in Step 3.")

    st.markdown("### What the Guardian checked")
    log = {e["agent"][:2]: e for e in report.get("agent_log", [])}
    rows = [("1.", "Discover components", f"{len(inventory['manifests'])} manifests, {inv_s['npm_packages']} packages, direct and transitive"),
            ("2.", "Build the supply chain view", f"CycloneDX SBOM, dependency graph, {inv_s['container_images']} images and {inv_s['ci_actions']} CI actions inspected"),
            ("3.", "Detect vulnerabilities", f"{m['vulnerabilities']} advisories with severity, CVSS, fix and path"),
            ("4.", "Detect suspicious changes", f"7 checks against {susp['base_ref']}: {len(changes)} changes, {len(posture)} standing observations"),
            ("5.", "Present evidence", "evidence report (PDF, JSON, Markdown), raw scanner output, SHA-256 hashes")]
    html = ""
    for k, name, ev in rows:
        e = log.get(k) if k != "5." else {"status": "ok" if pdf_path.exists() else "error"}
        ok = e and e.get("status") == "ok"
        html += (f'<div class="cover"><div class="{"ok" if ok else "bad"}">{"✓" if ok else "✕"}</div>'
                 f'<div><b>{k} {name}</b><div class="ev">{escape(ev)}</div></div><div class="ev">{"done" if ok else "not done"}</div></div>')
    st.markdown(html, unsafe_allow_html=True)


def components_page():
    section("1 · Components", f"Everything the application installs, read from <code>package-lock.json</code> so packages pulled in by "
            f"other packages are included. {inv_s['direct']} were chosen in package.json; {inv_s['transitive']} came along with them.")
    c = st.columns(5)
    for col, (k, v) in zip(c, [("Installed", inv_s["npm_packages"]), ("Chosen directly", inv_s["direct"]),
                               ("Pulled in", inv_s["transitive"]), ("Development only", inv_s["dev"]),
                               ("Run install scripts", inv_s["packages_with_install_scripts"])]):
        col.metric(k, v)
    if ddf.empty:
        return
    st.markdown("### Look up a package")
    pkgs = sorted(ddf.name.unique())
    vnames = set(vdf.package) if not vdf.empty else set()
    trace = report["trace"]["package"].rsplit("@", 1)[0] if report.get("trace") else None
    pick = st.selectbox("Package", pkgs, index=pkgs.index(trace) if trace in pkgs else 0,
                        format_func=lambda n: n + ("  — has advisories" if n in vnames else ""))
    rows = ddf[ddf.name == pick]
    _, nodes = load_graph(str(gpath), gpath.stat().st_mtime) if gpath.exists() else (None, {})
    f = st.columns(4)
    f[0].markdown(f"**Installed versions**  \n{', '.join(sorted(rows.version.unique()))}")
    f[1].markdown(f"**Chosen directly?**  \n{'Yes, in package.json' if rows.type.eq('direct').any() else 'No, pulled in'}")
    f[2].markdown(f"**Licence**  \n{', '.join(sorted(set(rows.license.fillna('not declared'))))}")
    f[3].markdown(f"**Runs code on install?**  \n{'Yes' if rows.has_install_script.any() else 'No'}")
    for _, r in rows.iterrows():
        info = nodes.get(r.lock_path)
        if info:
            st.markdown(f"Version **{r.version}** ({'shipped' if r.scope != 'dev' else 'dev only'}) arrives through: "
                        + " → ".join(f"`{x}`" for x in info["shortest_path"]))
    pr = [r for r in recs if r["package"] == pick]
    for r in pr:
        st.markdown(f"**Remediation ({r['installed_version']}):** {r['headline']}")

    st.markdown("### All packages")
    a, b, c = st.columns([2, 1, 1])
    q = a.text_input("Filter by name", placeholder="e.g. express")
    kind = b.selectbox("Chosen or pulled in", ["All", "Chosen directly", "Pulled in"])
    scope = c.selectbox("Used in", ["All", "Shipped", "Development only"])
    view = ddf.copy()
    if q:
        view = view[view.name.str.contains(q, case=False, regex=False)]
    if kind != "All":
        view = view[view.type == ("direct" if kind == "Chosen directly" else "transitive")]
    if scope != "All":
        view = view[(view.scope == "dev") == (scope == "Development only")]
    st.dataframe(view[["name", "version", "type", "scope", "license", "declared_range", "has_install_script", "lock_path"]],
                 hide_index=True, width="stretch", height=340)
    st.caption(f"{len(view)} of {len(ddf)} packages shown.")

    a, b = st.columns(2, gap="large")
    with a:
        st.markdown("### Manifests and lockfiles found")
        st.dataframe(pd.DataFrame(inventory["manifests"]), hide_index=True, width="stretch", height=260)
    with b:
        st.markdown("### Licences")
        df = ddf.assign(group=ddf.license.map(analysis.licence_group))
        order = ["Permissive", "Weak copyleft", "Strong copyleft", "Other", "Not declared"]
        cnt = df.group.value_counts()
        gdf = pd.DataFrame({"group": [o for o in order if o in cnt], "packages": [int(cnt[o]) for o in order if o in cnt]})
        st.altair_chart(bar(gdf, "packages", "group", height=150, sort=list(gdf.group), color_enc=alt.Color(
            "group:N", legend=None, scale=alt.Scale(domain=order, range=[GREEN, AMBER, RED, MUTED, "#6B7C8F"]))), width="stretch")
        review = df[df.group != "Permissive"]
        st.caption(f"{len(review)} packages to review for licence: " + ", ".join(f"{r.name}@{r.version}" for r in review.head(12).itertuples()))
    sprawl = ddf.groupby("name").version.nunique()
    sprawl = sprawl[sprawl > 1].sort_values(ascending=False)
    st.markdown(f"### Same package, several versions ({len(sprawl)})")
    if len(sprawl):
        st.dataframe(pd.DataFrame({"package": sprawl.index, "versions": [", ".join(sorted(ddf[ddf.name == n].version.unique()))
                                                                        for n in sprawl.index]}), hide_index=True, width="stretch", height=220)


def supply_chain_page():
    section("2 · Supply chain view", "The formal bill of materials, where every component comes from, and how each one reaches "
            "the application, including the container images and CI/CD workflows that build it.")
    sb = report.get("sbom") or {}
    a, b = st.columns([3, 2], gap="large")
    with a:
        st.markdown("### Software bill of materials")
        st.markdown(f"**{sb.get('format', '?')} {sb.get('spec_version', '')}** generated by **{sb.get('tool', '?')}**, "
                    f"{sb.get('component_count', 0)} components. {sb.get('matched_inventory', 0)} of its {sb.get('npm_component_count', 0)} "
                    f"npm components match the lockfile exactly.")
        if sb.get("path") and Path(sb["path"]).exists():
            st.download_button("Download SBOM (CycloneDX JSON)", Path(sb["path"]).read_bytes(), Path(sb["path"]).name, "application/json")
    with b:
        st.markdown("### Where components come from")
        st.dataframe(pd.DataFrame(analysis.origins(deps), columns=["source", "packages"]), hide_index=True, width="stretch")
    if not gpath.exists():
        return
    g, nodes = load_graph(str(gpath), gpath.stat().st_mtime)
    depth, size = graph_stats(str(gpath), gpath.stat().st_mtime)
    vulnerable = {f"{v['package']}@{v['installed_version']}" for v in findings}
    vn = {n for n in g.nodes if g.nodes[n]["label"] in vulnerable}

    st.markdown("### Vulnerability map")
    st.markdown(f'<p class="note">The project sits in the centre; the ring of dots is its {len(size)} direct dependencies. Red '
                f'circles have advisories, and orange arrows show how each one reaches the application.</p>', unsafe_allow_html=True)
    if vn:
        routes = st.radio("Routes per vulnerable package", [1, 2, 3], horizontal=True, key="routes")
        st.markdown('<div style="max-width:980px;margin:0 auto">' + vuln_graph.radial_svg(g, vn, per_node=routes, dark=True)
                    + "</div>", unsafe_allow_html=True)
        legend = "".join(f'<span class="swatch" style="background:{c}"></span>{escape(n)}' for n, c in
                         [("project", "#2F6FBF"), ("direct", vuln_graph.BLUE), ("level 2", vuln_graph.LEVEL[2]),
                          ("level 3+", vuln_graph.LEVEL[3]), ("has advisories", vuln_graph.RED), ("path to it", vuln_graph.ORANGE)])
        st.markdown(f'<p class="note">{legend}</p>', unsafe_allow_html=True)
    else:
        st.markdown("No package in this tree has known advisories.")

    a, b = st.columns([3, 2], gap="large")
    with a:
        st.markdown("### Heaviest direct dependencies")
        leads = set().union(*(nx.ancestors(g, v) | {v} for v in vn)) if vn else set()
        big = pd.DataFrame([{"dependency": g.nodes[n]["label"], "packages brought in": c,
                             "status": "advisories underneath" if n in leads else "none known"}
                            for n, c in sorted(size.items(), key=lambda x: -x[1])[:12]])
        st.altair_chart(bar(big, "packages brought in", "dependency", height=360, color_enc=alt.Color(
            "status:N", scale=alt.Scale(domain=["advisories underneath", "none known"], range=[ORANGE, BLUE]),
            legend=alt.Legend(orient="bottom", title=None))), width="stretch")
    with b:
        st.markdown("### Packages at each depth")
        lv = Counter(v for n, v in depth.items() if n != "ROOT")
        st.altair_chart(alt.Chart(pd.DataFrame({"depth": [str(x) for x in sorted(lv)], "packages": [lv[x] for x in sorted(lv)]}))
                        .mark_bar(color="#6F8BA8", cornerRadiusEnd=2).encode(
            x=alt.X("depth:N", sort=None, title="depth (1 = listed in package.json)"), y=alt.Y("packages:Q", title=None),
            tooltip=["depth", "packages"]).properties(height=360), width="stretch")

    st.markdown("### Trace a package to where it originates")
    only = st.toggle("Only packages with advisories", value=bool(vn))
    pool = sorted(vn if (only and vn) else set(g.nodes) - {"ROOT"}, key=lambda n: g.nodes[n]["label"])
    tp = report["trace"]["package"] if report.get("trace") else None
    target = st.selectbox("Package ", pool, index=next((i for i, n in enumerate(pool) if g.nodes[n]["label"] == tp), 0),
                          format_func=lambda n: g.nodes[n]["label"])
    info, sp = nodes[target], nodes[target]["shortest_path"]
    if g.nodes[target].get("direct"):
        st.markdown(f"`{info['label']}` is listed in package.json, so someone chose it.")
    else:
        st.markdown(f"Nobody chose `{info['label']}`. It arrives through `{sp[1] if len(sp) > 1 else '?'}`, {len(sp) - 1} levels down. "
                    "Direct dependencies that lead to it: " + ", ".join(f"`{x}`" for x in info["introduced_via"]) + ".")
    dep_row = ddf[ddf.lock_path == target] if not ddf.empty else ddf
    if len(dep_row) and dep_row.iloc[0].resolved:
        st.markdown(f"Downloaded from: `{dep_row.iloc[0].resolved}`")
    paths = sorted((p for _, p in zip(range(25), nx.all_simple_paths(g, "ROOT", target, cutoff=12))), key=len)[:3]
    st.graphviz_chart(paths_dot(g, paths, target, vulnerable))

    st.markdown("### Container images and CI/CD workflows inspected")
    other = [c for c in inventory["components"] if c["ecosystem"] != "npm"]
    if other:
        odf = pd.DataFrame(other)[["ecosystem", "name", "version", "pinning", "source_file"]]
        st.dataframe(odf, hide_index=True, width="stretch", height=260)
        imgs = [c for c in other if c["ecosystem"] == "docker"]
        acts = [c for c in other if c["ecosystem"] == "github-actions"]
        st.caption(f"{sum(c['pinning'] != 'digest' for c in imgs)} of {len(imgs)} images are not pinned by digest; "
                   f"{sum(c['pinning'] != 'sha' for c in acts)} of {len(acts)} CI action references are not pinned to a commit SHA.")

    st.markdown("### Browse the whole tree")
    show_html(tree_html(g, vn, dark=True), 640)


def vulnerabilities_page():
    src = {"npm-audit": "npm audit (GitHub Advisory Database)", "osv": "OSV-Scanner (osv.dev)"}.get(vulns.get("scanner"), vulns.get("scanner"))
    section("3 · Vulnerabilities", f"Known advisories for the exact installed versions, reported by {src}. Each one comes with its "
            "severity, CVSS score where published, the version that fixes it, how it reaches the application, and what to do about it.")
    if vdf.empty:
        st.markdown("No known advisories for the installed versions.")
        return
    c = st.columns(5)
    for col, s in zip(c, ["critical", "high", "moderate", "low"]):
        col.metric(s.title(), sev.get(s, 0))
    c[4].metric("With a fixed version", int(vdf.fixed_version.notna().sum()))

    st.markdown("### Remediation, package by package")
    st.markdown('<p class="note">From the scanner\'s own fix data and each advisory\'s fixed version. P1 = critical or high in '
                'shipped code, P2 = other shipped issues or critical/high dev-only, P3 = the rest. Nothing is changed automatically.</p>',
                unsafe_allow_html=True)
    if recs:
        upg = Counter(r["headline"] for r in recs if r["headline"].startswith("Upgrade"))
        if upg:
            idf = pd.DataFrame([{"upgrade": h.replace("Upgrade ", ""), "vulnerable packages cleared": n} for h, n in upg.most_common(8)])
            st.markdown("**Vulnerable packages each upgrade clears**")
            st.altair_chart(bar(idf, "vulnerable packages cleared", "upgrade", BLUE, 40 + 30 * len(idf)), width="stretch")
        pick_p = st.radio("Show", ["All", "P1 only", "P2", "P3"], horizontal=True)
        for r in recs:
            if pick_p != "All" and not r["priority"].startswith(pick_p[:2]):
                continue
            with st.expander(f"{r['priority'][:2]}  ·  {r['package']}@{r['installed_version']}  ·  {r['worst_severity']}  ·  {r['headline']}"):
                via = "Listed in package.json." if r["direct"] else "Pulled in by " + ", ".join(f"`{v}`" for v in r["introduced_via"][:3]) + "."
                st.markdown(f"{via} Used in: **{'shipped code' if r['scope'] == 'prod' else 'development only'}**.")
                st.markdown("**What to do**")
                for s_ in r["steps"]:
                    st.markdown(f"- {s_}")
                adv = vdf[(vdf.package == r["package"]) & (vdf.installed_version == r["installed_version"])]
                st.dataframe(adv.assign(cve=adv.aliases.map(", ".join), cwe=adv.cwe.map(lambda x: ", ".join(x)))[
                    ["id", "cve", "severity", "cvss", "fixed_version", "title", "reference"]], hide_index=True, width="stretch",
                    column_config={"reference": st.column_config.LinkColumn("source")})

    st.markdown("### All advisories")
    df = vdf.copy()
    df["type"] = df.direct.map({True: "direct", False: "pulled in"})
    df["path"] = df.dependency_path.map(lambda p: " → ".join(p))
    df["aliases"] = df.aliases.map(", ".join)
    df["cwe"] = df.cwe.map(lambda x: ", ".join(x))
    a, b, c = st.columns(3)
    sevs = [s for s in analysis.SEVERITIES if s in set(df.severity)]
    ps = a.multiselect("Severity", sevs, sevs)
    pu = b.selectbox("Used in ", ["All", "Shipped", "Development only"])
    pf = c.selectbox("Fix", ["All", "Fixed version available", "No fix published"])
    view = df[df.severity.isin(ps)]
    if pu != "All":
        view = view[(view.scope != "prod") == (pu == "Development only")]
    if pf != "All":
        view = view[view.fixed_version.notna() == (pf == "Fixed version available")]
    st.dataframe(view[["id", "aliases", "severity", "cvss", "package", "installed_version", "fixed_version", "type", "scope",
                       "cwe", "title", "path", "reference"]], hide_index=True, width="stretch", height=420,
                 column_config={"reference": st.column_config.LinkColumn("source"),
                                "cvss": st.column_config.NumberColumn("CVSS", format="%.1f")})
    st.caption(f"{len(view)} of {len(df)} advisories shown. Raw scanner output is saved in {out.relative_to(ROOT).as_posix()}/raw.")


def changes_page():
    section("4 · Suspicious changes", f"What changed in package.json, the lockfile, Dockerfiles and CI workflows since "
            f"<code>{escape(str(susp['base_ref']))}</code>. Scripts are read as text and never run. Pick an older commit under "
            f"<b>Inspection settings</b> in the sidebar, then <b>Inspect again</b>, to look further back.")
    found = Counter(f["category"] for f in changes)
    standing = Counter()
    for f in posture:
        ev = f.get("evidence") or {}
        standing[f["category"]] += len(ev.get("packages") or ev.get("actions") or ev.get("entries") or []) or 1
    total_anoms = sum(found.values()) + sum(standing.values())
    st.markdown(f"### Checks performed ({total_anoms} anomal{'y' if total_anoms == 1 else 'ies'} identified)")
    html = ""
    for cat, name in CHECKS:
        n, k = found.get(cat, 0), standing.get(cat, 0)
        mark, cls = ("!", "bad") if (n or k) else ("✓", "ok")
        html += (f'<div class="cover"><div class="{cls}">{mark}</div><div><b>{name}</b></div>'
                 f'<div class="ev">{n} since baseline · {k} in current code</div></div>')
    st.markdown(html, unsafe_allow_html=True)
    for note in susp.get("notes", []):
        st.caption(note)
    st.markdown(f"### Changes since {susp['base_ref']} ({len(changes)})")
    if not changes:
        st.markdown("Nothing suspicious changed since this baseline.")
    for f in changes:
        with st.expander(f"{f['severity'].title()}: {f['title']}", expanded=f["severity"] in ("critical", "high")):
            st.markdown(f"`{f['file']}`  \n**Why it matters:** {f['why_suspicious']}")
            if f["before"] is not None or f["after"] is not None:
                l, r = st.columns(2)
                l.markdown("Before")
                l.code(f["before"] or "(not present)", wrap_lines=True)
                r.markdown("After")
                r.code(f["after"] or "(not present)", wrap_lines=True)
            st.markdown(f"**Remediation:** {f.get('remediation', '')}")
            if f["evidence"]:
                st.json(f["evidence"], expanded=False)
    st.markdown(f"### Standing observations ({len(posture)})")
    st.markdown('<p class="note">True of the current code whatever the baseline.</p>', unsafe_allow_html=True)
    for f in posture:
        with st.expander(f"{f['severity'].title()}: {f['title']}"):
            st.markdown(f"`{f['file']}`  \n{f['why_suspicious']}")
            st.markdown(f"**Remediation:** {f.get('remediation', '')}")
            if f["evidence"]:
                st.json(f["evidence"], expanded=False)


def evidence_page():
    section("5 · Evidence & report", "Everything the inspection produced: the written report, the agents' run, and every raw file "
            "with its SHA-256 hash so any finding can be checked independently.")
    a, b = st.columns([2, 3], gap="large")
    with a:
        st.markdown("### Evidence report")
        if pdf_path.exists():
            st.download_button("Download evidence report (PDF)", pdf_path.read_bytes(), f"{repo.name}-evidence-report.pdf",
                               "application/pdf", type="primary", width="stretch", key="pdf_ev")
            st.caption("Cover with grade and checkpoint, executive summary, components, supply chain view with the vulnerability map, "
                       "every advisory, the remediation plan, suspicious changes, licences and an evidence appendix.")
        if st.button("Rebuild the PDF from these results", width="stretch"):
            from guardian.pdf_report import build_pdf
            build_pdf(out)
            st.rerun()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(out.rglob("*")):
                if f.is_file() and (f.parent == out or f.parent.name == "raw"):
                    z.write(f, f.relative_to(out))
        st.download_button("All results (ZIP)", buf.getvalue(), f"{repo.name}-guardian.zip", "application/zip", width="stretch")
        for name, mime in [("fix_recommendations.csv", "text/csv"), ("evidence_report.md", "text/markdown"),
                           ("vulnerability_graph.svg", "image/svg+xml"), ("dependency_graph.html", "text/html")]:
            if (out / name).exists():
                st.download_button(name, (out / name).read_bytes(), name, mime, width="stretch")
    with b:
        st.markdown("### Summary")
        st.caption(f"Written by {report['interpretation']['source']}")
        st.markdown(report["interpretation"]["text"])
    st.markdown("### Agent run")
    st.graphviz_chart(pipeline_dot(report["agent_log"]))
    st.dataframe(pd.DataFrame(report["agent_log"]), hide_index=True, width="stretch")
    st.markdown("### Evidence files")
    rows = [{"file": f.relative_to(out).as_posix(), "bytes": f.stat().st_size, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
            for f in sorted(out.rglob("*")) if f.is_file() and (f.parent == out or f.parent.name == "raw") and f.name != "history.jsonl"]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    hist = out / "history.jsonl"
    if hist.exists():
        h = [json.loads(l) for l in hist.read_text(encoding="utf-8").splitlines() if l.strip()]
        st.markdown(f"### Inspection history ({len(h)})")
        st.dataframe(pd.DataFrame([{"inspected": when(r["at"]), "commit": (r.get("commit") or "")[:9], "baseline": r.get("base_ref"),
                                    "packages": r["npm_packages"], "advisories": r["vulnerabilities"],
                                    "critical": r["by_severity"].get("critical", 0), "changes": r["suspicious_changes"]} for r in h][::-1]),
                     hide_index=True, width="stretch")


def compare_page():
    section("Compare repositories", "Every repository inspected on this machine, side by side. Pick one in the sidebar to open it.")
    rows = []
    for p in repos:
        r = load(out_dir_for(p), "evidence_report.json")
        if not r:
            rows.append({"repository": p.name, "inspected": "not yet"})
            continue
        f2 = (load(out_dir_for(p), "vulnerability_findings.json") or {"findings": []})["findings"]
        s2 = (load(out_dir_for(p), "suspicious_changes.json") or {"findings": []})["findings"]
        inv2 = load(out_dir_for(p), "inventory.json") or {"components": []}
        sc, letter, _, _ = analysis.risk_grade(f2, [x for x in s2 if x["kind"] == "change"], inv2)
        mm_, sv = r["metrics"], r["metrics"]["vulnerabilities_by_severity"]
        rows.append({"repository": p.name, "grade": f"{letter} ({sc})", "inspected": when(r["generated_at"]),
                     "packages": mm_["npm_packages"], "chosen": mm_["direct_dependencies"], "advisories": mm_["vulnerabilities"],
                     "critical": sv.get("critical", 0), "high": sv.get("high", 0), "changes": mm_["suspicious_changes"]})
    table = pd.DataFrame(rows)
    st.dataframe(table, hide_index=True, width="stretch")
    if "advisories" in table and table.advisories.notna().any():
        scanned = table.dropna(subset=["advisories"])
        long = scanned.melt(id_vars="repository", value_vars=["critical", "high"], var_name="severity", value_name="count")
        long["count"] = long["count"].astype(int)
        st.altair_chart(bar(long, "count", "repository", height=60 + 46 * len(scanned), color_enc=alt.Color(
            "severity:N", scale=alt.Scale(domain=["critical", "high"], range=[RED, ORANGE]),
            legend=alt.Legend(orient="bottom", title=None))).properties(height=alt.Step(42)), width="stretch")


nav.run()
