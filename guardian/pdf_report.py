"""Professional PDF evidence report, built only from the scan outputs in a reports folder."""
import hashlib
import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

import networkx as nx
from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (CondPageBreak, Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from guardian import analysis, vuln_graph

INK, STEEL, LINE, PAPER = colors.HexColor("#1B2A3A"), colors.HexColor("#5E6E7E"), colors.HexColor("#D3DBE2"), colors.HexColor("#F4F6F7")
BLUE, RED, AMBER, GREEN, ORANGE = (colors.HexColor(c) for c in ("#1F5FAE", "#B3261E", "#C98A00", "#2E7D5B", "#D9622B"))
SEV_COLOR = {"critical": RED, "high": ORANGE, "moderate": AMBER, "medium": AMBER, "low": BLUE}
GRADE_COLOR = {"A": GREEN, "B": GREEN, "C": AMBER, "D": ORANGE, "F": RED}
W = A4[0] - 30 * mm

S = {
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=5),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=10.5, textColor=STEEL),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.8, leading=9.6, textColor=INK),
    "cellmono": ParagraphStyle("cellmono", fontName="Courier", fontSize=7.4, leading=9.4, textColor=INK),
    "cellhead": ParagraphStyle("cellhead", fontName="Helvetica-Bold", fontSize=7.8, leading=9.6, textColor=colors.white),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=INK, spaceBefore=4, spaceAfter=8),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=INK, spaceBefore=10, spaceAfter=5),
    "kicker": ParagraphStyle("kicker", fontName="Helvetica", fontSize=9, leading=12, textColor=STEEL),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=30, leading=34, textColor=INK, spaceAfter=6),
    "lead": ParagraphStyle("lead", fontName="Helvetica", fontSize=11, leading=15.5, textColor=INK, spaceAfter=8),
}


def t(text) -> str:
    """Escape for reportlab's mini-markup and swap characters the base PDF fonts lack."""
    s = escape(str(text if text is not None else ""))
    return s.replace("→", "-&gt;").replace("…", "...").replace("≥", "&gt;=").replace("✓", "yes")


def P(text, style="body"):
    return Paragraph(t(text), S[style])


def PM(markup, style="body"):  # caller supplies already-escaped markup
    return Paragraph(markup, S[style])


def load(out: Path, name: str):
    p = out / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def table(rows, widths, head=True, zebra=True, extra=()):
    tb = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if head:
        style += [("BACKGROUND", (0, 0), (-1, 0), INK)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1 if head else 0), (-1, -1), [colors.white, PAPER])]
    tb.setStyle(TableStyle(style + list(extra)))
    return tb


def head(*cols):
    return [Paragraph(t(c), S["cellhead"]) for c in cols]


def sev_cell(sev):
    c = SEV_COLOR.get(sev, STEEL)
    return Paragraph(f'<font color="{c.hexval().replace("0x", "#")}"><b>{t(sev)}</b></font>', S["cell"])


class Stamp(Flowable):
    """Customs-style inspection stamp: grade letter + verdict."""

    def __init__(self, letter, verdict, score, color, w=62 * mm, h=26 * mm):
        super().__init__()
        self.letter, self.verdict, self.score, self.color, self.width, self.height = letter, verdict, score, color, w, h

    def draw(self):
        c = self.canv
        c.saveState()
        c.translate(self.width / 2, self.height / 2)
        c.rotate(-4)
        c.setStrokeColor(self.color)
        c.setLineWidth(2.6)
        c.roundRect(-self.width / 2, -self.height / 2, self.width, self.height, 6, stroke=1, fill=0)
        c.setLineWidth(0.9)
        c.roundRect(-self.width / 2 + 3, -self.height / 2 + 3, self.width - 6, self.height - 6, 4, stroke=1, fill=0)
        c.setFillColor(self.color)
        c.setFont("Helvetica-Bold", 40)
        c.drawString(-self.width / 2 + 9, -14, self.letter)
        c.setFont("Helvetica-Bold", 12.5)
        c.drawString(-self.width / 2 + 40, 2, self.verdict.upper())
        c.setFont("Helvetica", 8.5)
        c.drawString(-self.width / 2 + 40, -11, f"score {self.score} of 100")
        c.restoreState()


def graph_drawing(out: Path, findings: list, max_w=W, max_h=150 * mm):
    gpath = out / "dependency_graph.json"
    if not gpath.exists() or not findings:
        return None
    data = json.loads(gpath.read_text(encoding="utf-8"))
    g = nx.DiGraph()
    for n in data["nodes"]:
        g.add_node(n["id"], **{k: n[k] for k in ("label", "name", "version", "direct", "scope")})
    g.add_edges_from((e["from"], e["to"]) for e in data["edges"])
    labels = {f"{f['package']}@{f['installed_version']}" for f in findings}
    vn = {n for n in g if g.nodes[n]["label"] in labels}
    if not vn:
        return None
    L = vuln_graph.radial_layout(g, vn)
    pos, sizes = L["pos"], L["sizes"]
    pad = 170
    xs, ys = [x for x, _ in pos.values()], [y for _, y in pos.values()]
    minx, maxx, miny, maxy = min(xs) - pad, max(xs) + pad, min(ys) - 60, max(ys) + 60
    k = min(max_w / (maxx - minx), max_h / (maxy - miny))
    d = Drawing((maxx - minx) * k, (maxy - miny) * k)
    X = lambda x: (x - minx) * k
    Y = lambda y: (maxy - y) * k
    wire, orange = colors.HexColor("#C9D3DC"), ORANGE
    for c, par in L["parent"].items():
        if c in pos and par in pos and (par, c) not in L["hot"]:
            (x1, y1), (x2, y2) = pos[par], pos[c]
            d.add(Line(X(x1), Y(y1), X(x2), Y(y2), strokeColor=wire, strokeWidth=0.4))
    import math
    for a, b in L["hot"]:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1
        ex, ey = x2 - dx / dist * (sizes[b] + 3), y2 - dy / dist * (sizes[b] + 3)
        d.add(Line(X(x1), Y(y1), X(ex), Y(ey), strokeColor=orange, strokeWidth=1.3))
        ux, uy = dx / dist, dy / dist
        hx, hy = ex - ux * 14, ey - uy * 14
        d.add(Polygon([X(ex), Y(ey), X(hx - uy * 7), Y(hy + ux * 7), X(hx + uy * 7), Y(hy - ux * 7)],
                      fillColor=orange, strokeColor=None))
    for n, (x, y) in pos.items():
        r = sizes[n] * k
        fill = colors.HexColor(L["fills"][n])
        ring = orange if (n in L["on_path"] and n not in L["vuln"]) else None
        d.add(Circle(X(x), Y(y), r, fillColor=fill, strokeColor=ring, strokeWidth=1.2 if ring else 0))
        if n == vuln_graph.ROOT:
            d.add(String(X(x), Y(y) - 3, L["root_name"], fontName="Helvetica-Bold", fontSize=max(6, 15 * k),
                         fillColor=colors.white, textAnchor="middle"))
        elif n in L["on_path"]:
            name, _, ver = L["label"][n].rpartition("@")
            tx, ty, anchor = vuln_graph.label_anchor(x, y, sizes[n])
            fs = max(5.2, 15 * k)
            d.add(String(X(tx), Y(ty), name, fontName="Helvetica-Bold" if n in L["vuln"] else "Helvetica",
                         fontSize=fs, fillColor=INK, textAnchor=anchor))
            d.add(String(X(tx), Y(ty) - fs * 1.1, "@" + ver, fontName="Helvetica", fontSize=fs * 0.85,
                         fillColor=STEEL, textAnchor=anchor))
    return d


def legend():
    items = [("Project", "#1B2A3A"), ("Direct dependency", "#1F5FAE"), ("Indirect (lighter = deeper)", "#9DB6D3"),
             ("Has advisories", "#B3261E"), ("Path to a vulnerable package", "#D9622B")]
    return PM("&nbsp;&nbsp;".join(f'<font color="{c}">&#9632;</font> {t(n)}' for n, c in items), "small")


def file_hashes(out: Path):
    rows = []
    for f in sorted(out.rglob("*")):
        if f.is_file() and f.suffix != ".pdf" and f.name != "history.jsonl" and (f.parent == out or f.parent.name == "raw"):
            rows.append((f.relative_to(out).as_posix(), f.stat().st_size, hashlib.sha256(f.read_bytes()).hexdigest()))
    return rows


def build_pdf(out: Path, repo_name: str = None) -> Path:
    report, inventory = load(out, "evidence_report.json"), load(out, "inventory.json")
    deps_doc, vulns = load(out, "dependency_inventory.json") or {}, load(out, "vulnerability_findings.json") or {"findings": []}
    susp = load(out, "suspicious_changes.json") or {"findings": [], "base_ref": "HEAD", "notes": []}
    recs = load(out, "fix_recommendations.json") or []
    graph = load(out, "dependency_graph.json")
    if not report or not inventory:
        raise FileNotFoundError("Run a scan first: evidence_report.json or inventory.json is missing.")
    repo_name = repo_name or Path(report["repo"]).name
    deps = deps_doc.get("dependencies", [])
    findings = vulns["findings"]
    changes = [f for f in susp["findings"] if f["kind"] == "change"]
    posture = [f for f in susp["findings"] if f["kind"] == "baseline"]
    m, sev, inv_s = report["metrics"], report["metrics"]["vulnerabilities_by_severity"], inventory["summary"]
    score, letter, verdict, breakdown = analysis.risk_grade(findings, changes, inventory)
    cp = analysis.checkpoint(report, inventory, vulns, susp)
    when = datetime.fromisoformat(report["generated_at"]).strftime("%d %B %Y, %H:%M UTC")
    scanner = {"npm-audit": "npm audit (GitHub Advisory Database)", "osv": "OSV-Scanner (osv.dev)"}.get(vulns.get("scanner"), vulns.get("scanner"))
    path = out / "evidence_report.pdf"

    def footer(canv, doc):
        canv.saveState()
        canv.setStrokeColor(LINE)
        canv.line(15 * mm, 14 * mm, A4[0] - 15 * mm, 14 * mm)
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(STEEL)
        canv.drawString(15 * mm, 9.5 * mm, f"Software Supply Chain Guardian  |  Evidence report  |  {repo_name}")
        canv.drawRightString(A4[0] - 15 * mm, 9.5 * mm, f"Page {doc.page}")
        canv.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm,
                            bottomMargin=20 * mm, title=f"Evidence report: {repo_name}", author="Software Supply Chain Guardian",
                            subject="Software supply chain inspection")
    E = []

    # ---------- cover ----------
    E += [P("Software Supply Chain Guardian  |  Evidence report", "kicker"), Spacer(1, 4 * mm), P(repo_name, "title"),
          P("Know what you build. Trust what you ship. A five-agent inspection of the application's components, "
            "supply chain, known vulnerabilities and recent changes, with the evidence behind every finding.", "lead"), Spacer(1, 3 * mm)]
    fields = [("Commit", (report.get("commit") or "n/a")[:12]), ("Inspected", when), ("Vulnerability source", scanner),
              ("Changes compared with", str(susp.get("base_ref"))), ("Packages", f"{inv_s['npm_packages']} ({inv_s['direct']} direct)"),
              ("Advisories", f"{m['vulnerabilities']} ({sev.get('critical', 0)} critical, {sev.get('high', 0)} high)")]
    ftab = [[P(k, "small"), P(v, "cell")] for k, v in fields]
    E += [table(ftab, [38 * mm, W - 38 * mm], head=False, zebra=False,
                extra=[("LINEABOVE", (0, 0), (-1, 0), 1.5, INK)]), Spacer(1, 7 * mm)]
    E += [Table([[Stamp(letter, verdict, score, GRADE_COLOR[letter]),
                  P(f"Inspection result: grade {letter}, {verdict.lower()}. The grade starts at 100 and subtracts points "
                    f"for each real finding; the full breakdown is in section 1.", "body")]],
                colWidths=[70 * mm, W - 70 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]), Spacer(1, 7 * mm)]
    E += [P("Day 1 checkpoint", "h2")]
    E += [table([head("Question", "Answer from the evidence"),
                 [P("What is in the application?", "cell"), P(cp["inside"], "cell")],
                 [P("What changed?", "cell"), P(cp["changed"], "cell")],
                 [P("What appears risky?", "cell"), P(cp["risky"], "cell")]], [45 * mm, W - 45 * mm])]
    E += [Spacer(1, 6 * mm), P("Every fact in this report comes from a tool's output (lockfile, Syft, OSV-Scanner or npm audit, git). "
                               "Nothing is synthetic, and nothing from the inspected repository was executed. Raw evidence files "
                               "and their SHA-256 hashes are listed in the appendix.", "small"), PageBreak()]

    # ---------- 1. executive summary ----------
    prod_v = sum(f["scope"] == "prod" for f in findings)
    fixable = sum(1 for f in findings if f.get("fixed_version"))
    upg = Counter(r["headline"] for r in recs if r["headline"].startswith("Upgrade"))
    E += [P("1. Executive summary", "h1"),
          P(f"{repo_name} installs {inv_s['npm_packages']} npm packages, of which only {inv_s['direct']} were chosen directly. "
            f"The scanners report {m['vulnerabilities']} known advisories in "
            f"{len({(f['package'], f['installed_version']) for f in findings})} packages; {prod_v} affect code that ships to users "
            f"and {fixable} already have a fixed version. "
            + (f"{len(changes)} supply-chain changes were found since {susp['base_ref']}." if changes
               else f"No supply-chain changes were found since {susp['base_ref']}.")),
          ]
    if upg:
        top = upg.most_common(4)
        cleared = sum(n for _, n in top)
        E += [P(f"Highest-impact remediation: {', '.join(h.replace('Upgrade ', '') for h, _ in top)}. "
                f"These {len(top)} upgrades address {cleared} of the {len(recs)} vulnerable packages (section 6).")]
    E += [CondPageBreak(50 * mm), P("Risk grade breakdown", "h2")]
    if breakdown:
        E += [table([head("Finding", "Count", "Points each", "Deducted")] +
                    [[P(r["factor"], "cell"), P(r["count"], "cell"), P(r["points each"], "cell"), P(r["deducted"], "cell")]
                     for r in breakdown] + [[PM("<b>Score</b>", "cell"), P("", "cell"), P("", "cell"), PM(f"<b>{score} / 100</b>", "cell")]],
                    [W - 75 * mm, 20 * mm, 27 * mm, 28 * mm])]
    else:
        E += [P("No deductions: score 100.")]
    E += [P("A 90 or above, B 75, C 60, D 40, otherwise F.", "small")]

    # ---------- 2. scope and method ----------
    E += [P("2. Scope and method", "h1"),
          P("Five specialised agents run in a fixed order inside a LangGraph workflow. Each uses one tool and passes typed "
            "(Pydantic) results to the next through a shared state; a final report step combines them.")]
    tools = {"1.": ("Lockfile parser, manifest scan", "inventory.json"), "2.": ("Syft (fallback cyclonedx-npm)", "SBOM, CycloneDX"),
             "3.": ("NetworkX, Node resolution", "dependency_graph.json"), "4.": (scanner or "", "vulnerability_findings.json"),
             "5.": ("git diff, static inspection", "suspicious_changes.json")}
    rows = [head("Agent", "Tool", "Status", "Result")]
    for a in report.get("agent_log", []):
        tool = next((v[0] for k, v in tools.items() if a["agent"].startswith(k)), "")
        rows.append([P(a["agent"], "cell"), P(tool, "cell"), P(a["status"], "cell"), P(a["message"][:160], "cell")])
    E += [table(rows, [44 * mm, 38 * mm, 14 * mm, W - 96 * mm])]

    # ---------- 3. components ----------
    E += [CondPageBreak(60 * mm), P("3. Step 1: Components", "h1"),
          P(f"The Repository Discovery Agent found {len(inventory['manifests'])} manifest files and resolved the exact dependency "
            f"tree from package-lock.json, not just package.json, so transitive packages are included.")]
    E += [table([head("Measure", "Value")] + [[P(k, "cell"), P(v, "cell")] for k, v in [
        ("npm packages installed", inv_s["npm_packages"]), ("Chosen directly (package.json)", inv_s["direct"]),
        ("Pulled in (transitive)", inv_s["transitive"]), ("Shipped to production", inv_s["prod"]), ("Development only", inv_s["dev"]),
        ("Container image references", inv_s["container_images"]), ("CI action references", inv_s["ci_actions"]),
        ("Packages that run install scripts", inv_s["packages_with_install_scripts"])]], [90 * mm, W - 90 * mm])]
    kinds = Counter(mf["kind"] for mf in inventory["manifests"])
    E += [P("Manifests: " + ", ".join(f"{v} {k}" for k, v in kinds.items()) + ".", "small")]
    imgs = [c for c in inventory["components"] if c["ecosystem"] == "docker"]
    if imgs:
        E += [CondPageBreak(55 * mm), P("Container images inspected", "h2"),
              table([head("Image", "Tag or digest", "Pinning", "File")] +
                    [[P(c["name"], "cellmono"), P(c["version"], "cellmono"), P(c["pinning"], "cell"), P(c["source_file"], "cellmono")]
                     for c in imgs], [55 * mm, 35 * mm, 30 * mm, W - 120 * mm])]
    acts = [c for c in inventory["components"] if c["ecosystem"] == "github-actions"]
    if acts:
        unp = sorted({f"{c['name']}@{c['version']}" for c in acts if c["pinning"] != "sha"})
        E += [P(f"CI/CD workflows: {len(acts)} GitHub Action references; {len(acts) - sum(c['pinning'] != 'sha' for c in acts)} "
                f"pinned to a commit SHA" + (f"; not SHA-pinned: {', '.join(unp)}." if unp else "."), "body")]

    # ---------- 4. supply chain view ----------
    sb = report.get("sbom") or {}
    E += [CondPageBreak(80 * mm), P("4. Step 2: Supply chain view", "h1"),
          P(f"SBOM: {sb.get('format', '?')} {sb.get('spec_version', '')} generated by {sb.get('tool', '?')}, {sb.get('component_count', 0)} "
            f"components. {sb.get('matched_inventory', 0)} of its {sb.get('npm_component_count', 0)} npm components match the lockfile "
            f"inventory exactly.")]
    if graph:
        depth = {}
        for n in graph["nodes"]:
            depth[n["id"]] = len(n.get("shortest_path", [])) - 1
        E += [P(f"Dependency graph: {len(graph['nodes'])} nodes and {len(graph['edges'])} edges, up to {max(depth.values())} levels deep, "
                f"{len(graph.get('unresolved_edges', []))} unresolved edges.")]
    org = analysis.origins(deps)
    E += [CondPageBreak(40 * mm), P("Where components originate", "h2"),
          table([head("Source (from the lockfile's resolved URL)", "Packages")] + [[P(h, "cellmono"), P(n, "cell")] for h, n in org],
                [W - 30 * mm, 30 * mm])]
    if graph:
        direct = [n for n in graph["nodes"] if n.get("direct")]
        g2 = nx.DiGraph()
        g2.add_edges_from((e["from"], e["to"]) for e in graph["edges"])
        heavy = sorted(((n["label"], len(nx.descendants(g2, n["id"])) if n["id"] in g2 else 0) for n in direct), key=lambda x: -x[1])[:8]
        E += [CondPageBreak(50 * mm), P("Heaviest direct dependencies", "h2"),
              table([head("Direct dependency", "Packages it brings in")] + [[P(a, "cellmono"), P(b, "cell")] for a, b in heavy],
                    [W - 40 * mm, 40 * mm])]
    dr = graph_drawing(out, findings)
    if dr:
        E += [PageBreak(), P("Vulnerability map", "h2"),
              P("The project sits in the centre and the ring is its direct dependencies; outer rings are indirect levels. Red "
                "packages have advisories; orange arrows show the route by which each one enters the application."),
              dr, Spacer(1, 2 * mm), legend()]

    # ---------- 5. vulnerabilities ----------
    E += [PageBreak(), P("5. Step 3: Vulnerabilities", "h1"),
          P(f"Source: {scanner}. Each advisory is matched by the advisory database against the exact installed version. "
            f"Severity is the advisory's own rating; CVSS is shown where the advisory provides one. "
            f"Path shows how the package reaches the application.")]
    sc = [head("Severity", "Advisories", "In shipped code")]
    for s_ in analysis.SEVERITIES:
        if sev.get(s_):
            sc.append([sev_cell(s_), P(sev[s_], "cell"), P(sum(f["severity"] == s_ and f["scope"] == "prod" for f in findings), "cell")])
    E += [table(sc, [40 * mm, 30 * mm, 35 * mm]), Spacer(1, 3 * mm)]
    rows = [head("Advisory", "Severity", "CVSS", "Package", "Fixed in", "Used in", "How it gets in")]
    for f in sorted(findings, key=lambda f: (analysis.sev_rank(f["severity"]), f["package"])):
        adv = t(f["id"]) + (f'<br/><font size="6.5" color="#5E6E7E">{t(", ".join(f["aliases"][:2]))}</font>' if f.get("aliases") else "")
        adv += f'<br/><font size="6.5" color="#5E6E7E">{t(", ".join(f.get("cwe", [])[:2]))}</font>' if f.get("cwe") else ""
        rows.append([PM(adv, "cellmono"), sev_cell(f["severity"]), P(f.get("cvss") or "-", "cell"),
                     P(f"{f['package']}@{f['installed_version']}", "cellmono"), P(f.get("fixed_version") or "none", "cell"),
                     P(("direct, " if f["direct"] else "") + ("shipped" if f["scope"] == "prod" else "dev only"), "cell"),
                     P(" -> ".join(f.get("dependency_path", [])[1:]) or "-", "cell")])
    E += [table(rows, [33 * mm, 17.5 * mm, 11 * mm, 32 * mm, 15 * mm, 17 * mm, W - 125.5 * mm])]

    # ---------- 6. remediation ----------
    if recs:
        E += [PageBreak(), P("6. Remediation plan", "h1"),
              P("One recommendation per vulnerable package, from the scanner's own fix data (npm audit's fixAvailable) and each "
                "advisory's fixed version. P1 = critical or high in shipped code; P2 = other shipped issues or critical/high "
                "dev-only; P3 = the rest. Nothing has been applied; '(major)' means a major release that needs testing.")]
        acts_c = Counter(r["action"] for r in recs)
        E += [P("Actions: " + "; ".join(f"{k}: {v}" for k, v in acts_c.most_common()) + ".", "small"), Spacer(1, 2 * mm)]
        E += [table([head("Priority", "Package", "Severity", "Recommended fix")] +
                    [[P(r["priority"][:2], "cell"), P(f"{r['package']}@{r['installed_version']}", "cellmono"),
                      sev_cell(r["worst_severity"]), P(r["headline"], "cell")] for r in recs],
                    [16 * mm, 52 * mm, 19 * mm, W - 87 * mm])]
        E += [P("Steps for each package", "h2")]
        for r in recs:
            via = "listed in package.json" if r["direct"] else "pulled in by " + ", ".join(r["introduced_via"][:2])
            block = [PM(f"<b>{t(r['priority'][:2])}  {t(r['package'])}@{t(r['installed_version'])}</b>  "
                        f'<font color="#5E6E7E">{t(r["worst_severity"])}, {t(r["advisories"])} advisories, {t(via)}</font>', "body")]
            block += [PM("&bull; " + t(s_), "cell") for s_ in r["steps"]]
            block += [P("Advisories: " + ", ".join(r["ids"]), "small"), Spacer(1, 3 * mm)]
            E.append(KeepTogether(block))

    # ---------- 7. suspicious changes ----------
    E += [PageBreak(), P("7. Step 4: Suspicious changes", "h1"),
          P(f"The Anomaly Detection Agent compared package.json, the lockfile, Dockerfiles and CI workflows with git commit "
            f"{susp['base_ref']}, and inspected scripts as text without running them. Checks: unexpected dependency, look-alike "
            f"(typosquatted) name, suspicious version change, unsafe install script, untrusted or unpinned image, modified "
            f"lockfile, new CI dependency.")]
    for note in susp.get("notes", []):
        E += [P(note, "small")]
    if not changes:
        E += [P(f"No supply-chain changes since {susp['base_ref']}.")]
    for f in changes:
        block = [PM(f"<b>{t(f['id'])}  {t(f['title'])}</b>", "body"),
                 table([[P("Severity", "small"), sev_cell(f["severity"])], [P("File", "small"), P(f["file"], "cellmono")],
                        [P("Why it matters", "small"), P(f["why_suspicious"], "cell")],
                        [P("Before", "small"), P(f.get("before") or "(not present)", "cellmono")],
                        [P("After", "small"), P(f.get("after") or "(not present)", "cellmono")],
                        [P("Remediation", "small"), P(f.get("remediation", ""), "cell")]], [32 * mm, W - 32 * mm], head=False),
                 Spacer(1, 4 * mm)]
        E.append(KeepTogether(block))
    if posture:
        E += [CondPageBreak(50 * mm), P("Standing observations", "h2"), P("True of the current code regardless of the baseline.", "small"),
              table([head("Observation", "Severity", "Remediation")] +
                    [[P(f["title"], "cell"), sev_cell(f["severity"]), P(f.get("remediation", ""), "cell")] for f in posture],
                    [70 * mm, 18 * mm, W - 88 * mm])]

    # ---------- 8. licences and hygiene ----------
    if deps:
        groups = Counter(analysis.licence_group(d.get("license")) for d in deps)
        flagged = [d for d in deps if analysis.licence_group(d.get("license")) != "Permissive"]
        sprawl = Counter(d["name"] for d in deps)
        multi = sum(1 for n in {d["name"] for d in deps} if len({x["version"] for x in deps if x["name"] == n}) > 1)
        E += [CondPageBreak(70 * mm), P("8. Licences and hygiene", "h1"),
              table([head("Licence group", "Packages")] + [[P(k, "cell"), P(v, "cell")] for k, v in groups.most_common()], [90 * mm, 30 * mm]),
              Spacer(1, 2 * mm),
              P(f"{multi} packages are installed in more than one version. {len(flagged)} packages have a copyleft, unusual or "
                f"undeclared licence" + (": " + ", ".join(f"{d['name']}@{d['version']}" for d in flagged[:15]) + ("..." if len(flagged) > 15 else "") if flagged else "") + ".")]

    # ---------- appendix ----------
    E += [PageBreak(), P("Appendix: evidence files", "h1"),
          P("Every output of this inspection, with its SHA-256 hash, so the evidence can be verified independently. "
            "Files in raw/ are the scanners' untouched output.")]
    E += [table([head("File", "Bytes", "SHA-256")] + [[P(n, "cellmono"), P(f"{s_:,}", "cell"), P(h, "cellmono")] for n, s_, h in file_hashes(out)],
                [55 * mm, 18 * mm, W - 73 * mm])]
    E += [Spacer(1, 4 * mm), P(f"Report generated {datetime.now().strftime('%d %B %Y, %H:%M')} from the scan of {when}.", "small")]

    doc.build(E, onFirstPage=footer, onLaterPages=footer)
    return path
