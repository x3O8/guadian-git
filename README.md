# Software Supply Chain Guardian — Day 1 (Eyes) + Day 2 (Brain & Shield)

> Know what you build. Trust what you ship.

Team 18. An agentic AI guardian for npm applications, built and tested on **OWASP Juice Shop**.
Day 1 discovers the supply chain, detects risks and explains them with evidence. Day 2 prioritises the risks,
investigates non-CVE changes, recommends safe fixes, **waits for a human decision**, then validates each approved fix in a
sandbox (build, unit tests, rescan, before/after SBOM) and writes a verified report with a tamper-evident audit trail.
A benchmark compares the Guardian with npm audit, OSV-Scanner, Grype and Trivy on the same repositories.

## Architecture

```
Day 1 (LangGraph)  START → 1 Repository Discovery → 2 SBOM → 3 Dependency Analysis → 4 Vulnerability Detection
                         → 5 Anomaly Detection → report step → END

Day 2 (LangGraph)  START ─(phase=plan)→ 6 Risk Analysis → 7 Remediation → Human approval gate ─(nothing approved)→ wait
                                        (prioritise +                             │ approved   (phase=validate re-enters here)
                                         investigate)                             ▼
                                                              8 Validation & Report → END
                                                              (sandbox build/test/rescan, commit + approval tag, verified report)
```

| # | Agent | Source of truth | Output (in `reports/`, Day 2 in `reports/day2/`) |
|---|---|---|---|
| 1 | Repository Discovery | `package-lock.json`, `package.json`, Dockerfiles, compose, workflows | `inventory.json`, `dependency_inventory.json` |
| 2 | SBOM | Syft (fallback `@cyclonedx/cyclonedx-npm`) | `juice-shop-sbom.json` (CycloneDX 1.6) |
| 3 | Dependency Analysis | lockfile + Node resolution, NetworkX | `dependency_graph.json/.html`, `vulnerability_graph.svg` |
| 4 | Vulnerability Detection | OSV-Scanner (fallback npm audit / GitHub Advisory DB) | `vulnerability_findings.json`, `raw/` |
| 5 | Anomaly Detection | `git show <base>:file` vs working tree | `suspicious_changes.json` |
| 6 | Risk Analysis (prioritise + investigate) | CVSS, CISA KEV, FIRST EPSS, source imports, scope; lockfile + npm registry (scripts, integrity, provenance, deprecation) | `risk_priorities.json`, `investigations.json` |
| 7 | Remediation | npm audit fix data, advisory fixed versions, lockfile parent ranges | `remediation_plan.json` |
| – | Human approval gate | a named reviewer, in the dashboard or CLI | `decisions.json`, `audit_log.jsonl` |
| 8 | Validation & Report | git worktree branch, `npm ci --ignore-scripts`, build, unit tests, Day 1 agents again; then the verified report | `validation/<run>/…`, git branch + approval tag, `final/`, `verified_report.json/.md/.pdf` |

### Day 2 in one paragraph each

**Agent 6, Risk Analysis: prioritise.** Score = severity (CVSS × 4, max 40) + exploitability (CISA KEV 25, else EPSS percentile, else the CVSS vector, max 18) +
reachability (imported by app code 20, via an imported dependency 14, shipped but not imported 6, dev only 2) + exposure
(production web server 15). Tiers: Critical ≥ 80, High ≥ 65, Medium ≥ 45. Each point carries a one-line reason, and a confidence
says how much evidence was real (vector published? EPSS/KEV available? import found?). Non-CVE risks are scored on the same scale.

**Agent 6, Risk Analysis: investigate (non-CVE).** Install scripts are downloaded as text from the registry and classified (telemetry, binary download,
native build, risky patterns). Lockfile hashes are compared with the registry. Build provenance (npm attestations), deprecated packages,
download hosts, loose ranges, manifest/lockfile drift, image and CI pinning, and every change since the baseline are checked.
**Verified evidence** (fact + source) is always shown apart from **inference** (labelled AI or rule-based).

**Agent 7, Remediate.** For every vulnerable copy the agent works out which direct dependencies must move for that copy to disappear
(e.g. `jws` is shared by `jsonwebtoken` *and* `express-jwt`), then merges copies that share a change into one action. Actions are:
upgrade, upgrade the parent, pin with npm `overrides`, replace/remove, pin a container image by digest, pin a CI action to a SHA,
turn off install telemetry, block (revert a suspicious change), or escalate. Each states the exact change, expected risk reduction,
compatibility impact (semver jump + files that import it) and rollback.

**Human approval.** Approve, reject, accept the risk (reason + review date) or escalate. A reviewer name is required. Decisions are
tied to the action's content hash, so a changed plan needs a new decision. Nothing is applied without approval, and nothing is ever
merged, pushed or deployed automatically.

**Agent 8, Validate.** For a baseline and for each approved action, the agent creates a branch `guardian/<run>-<action>` in a sandbox
worktree (`sandbox/`, outside your copy). It commits a snapshot, applies the change, re-resolves the lockfile with scripts off,
runs `npm ci --ignore-scripts`, builds (`build:server`/`build`/`tsc`), runs unit tests (`test:server`/`test:unit`/`test`), loads each
changed package once, and rescans with the Day 1 agents. Results are compared with the baseline: advisories resolved and newly
introduced, before/after CycloneDX SBOM, added/removed packages, new install scripts, and build/test regressions. All passing
actions are then validated together as a release candidate. Logs and a `.patch` are kept; rollback = `git revert <commit>`.

**Final output.** Every fix that passed is committed together (the commit subject names the approver, `Approved-by:` trailers
record each approval, and an annotated tag `guardian-approved/<run>` is created in the approver's name) on `guardian/<run>-release-candidate` in the target repo's
own git (never merged into your branch, never pushed). `reports/day2/final/` holds `release-candidate.patch`, a `git am`-ready
`0001-Guardian-remediation.patch`, the fixed `package.json` + `package-lock.json` and `FINAL.md` (what, who approved, verdict,
how to review, merge and revert). Page 10 downloads it as a ZIP and can check the fix out as its own folder.

**Agent 8, Verify & report.** Each finding's journey: evidence → priority → action → decision → build & test → rescan → final status.
Remaining and accepted risk, final confidence with reasons, the audit trail (each entry hashes the previous one) and a
Responsible-AI note go into `verified_report.pdf`.

### LLM reasoning (optional) and its guard rails
Set `GROQ_API_KEY` to use Groq's `openai/gpt-oss-20b` for Day 2 reasoning. `GROQ_MODEL` overrides the model if needed.
Other Day 2 options include `ANTHROPIC_API_KEY` or an OpenAI-compatible endpoint (`GUARDIAN_LLM_BASE_URL`,
`GUARDIAN_LLM_API_KEY`, and `GUARDIAN_LLM_MODEL`). The LLM explains severity, suspicious changes, and the rationale for each fix. Every answer
is checked: if it names an advisory id or `package@version` that is not in that item's evidence, it is rejected and the rule-based
text is kept. Only package names, versions, advisory text and public registry data are sent. Prompts and responses go to
`reports/day2/llm_log.jsonl`. Without a key everything still works and is labelled "rule-based".

## Setup on Windows (CMD)

Install Python 3.10+ (tick "Add to PATH"), Node.js 22+ and Git for Windows. Then:

```cmd
cd C:\ssg\software-supply-chain-guardian
setup.bat
run.bat
```

- `setup.bat` (once): `.venv`, Python packages, `syft.exe` + `osv-scanner.exe` in `tools\`, git long paths, Juice Shop clone, lockfile.
- `run.bat`: Day 1 scan, Day 2 plan (stops at the approval gate), tests, then the dashboard on http://localhost:8501.
- `benchmark_tools.bat` (optional, once): downloads Grype and Trivy into `tools\` for the benchmark.

## Commands

```cmd
.venv\Scripts\activate
python -m guardian.cli --repo target\juice-shop                  :: Day 1 (agents 1-5)
python -m guardian.day2 plan                                     :: Day 2 agents 6-7, stops for approval
python -m guardian.day2 review --reviewer "Your Name"            :: approve / reject / accept / escalate in the terminal
python -m guardian.day2 validate                                 :: agent 8 for approved actions (each, then together)
python -m guardian.day2 validate --mode together                 :: faster: all approved actions in one sandbox run
python -m guardian.day2 status                                   :: plan, decisions, audit chain
python -m guardian.day2 checkout --reviewer "Your Name"          :: open the validated, committed fix as target\<repo>-fixed
python -m guardian.benchmark                                     :: compare tools on every repo in target\
python -m pytest -q                                              :: 38 tests
streamlit run app.py
```

Scan any public GitHub npm repo: paste its link under **Add a repository from GitHub** in the sidebar, or
`python -m guardian.cli --github https://github.com/OWASP/NodeGoat`, then `python -m guardian.day2 plan --repo target\NodeGoat`.

## Dashboard

| Group | Page | What it shows |
|---|---|---|
| Day 1 | Overview, 1–5 | Grade stamp, checkpoint, components, SBOM, supply-chain view, vulnerabilities, suspicious changes, evidence PDF |
| Day 2 | Day 2 overview | The six-station belt: prioritised risk → recommended fix → human approval → build & test → rescan → verified remediation; run buttons |
| Day 2 | 6 · Risk priorities | Stacked score bars (severity/exploitability/reachability/exposure), why each is severe, evidence, confidence |
| Day 2 | 6 · Suspicious changes | Non-CVE findings: verified evidence (green) beside inference (violet), verdict, remedy |
| Day 2 | 7 · Remediation & approval | Change requests with exact edit, risk reduction, compatibility, rollback; the decision form |
| Day 2 | 8 · Validation | Run the sandbox, release-candidate verdict, before/after numbers, per-fix steps, failing tests, SBOM diff, new advisories, patch, logs |
| Day 2 | 8 · Verified report | Final confidence, finding-by-finding status, remaining/accepted risk, audit trail with chain check, Responsible AI, PDF |
| Day 2 | Detection → verified fix | The final demonstration: one finding followed through all seven stops |
| Evaluate | Compare repositories / Benchmark | Grades side by side; precision/recall/F1 vs other tools, agreement, controlled non-CVE test, capabilities |

## Benchmark method

All installed tools scan the same `package.json` + `package-lock.json`. Findings are normalised to (package, version, vulnerability),
merging CVE/GHSA ids via the aliases the tools report (plus osv.dev lookups). The reference set is the consensus of independent
databases: reported by at least two of npm audit, OSV-Scanner, Grype and Trivy. The Guardian does not vote (it reuses OSV/npm audit).
Reported per tool: TP/FP/FN, precision, recall, F1 (overall and production-only), severity agreement, % with a fix, % with a path,
duplicates merged, runtime, and pairwise Jaccard agreement. Trivy runs with `--include-dev-deps` so scopes match.
A separate **controlled test** plants 8 non-CVE attacks (typosquat, install script, lockfile host, integrity, `:latest` image,
unpinned CI action, downgrade, unexpected dependency) plus 2 harmless controls in a throwaway local git repo, and records which
tools notice. It measures coverage of attack types, not real-world accuracy, and is labelled that way.

## Honesty notes
- Every finding comes from a tool's raw output (`reports/raw/`, `reports/day2/validation/…`). Nothing is synthetic.
- Day 2 validation runs the application's **own** build and unit tests inside the sandbox copy (that is what validating a fix means);
  dependency install scripts never run. Native modules (e.g. sqlite3) are therefore not built, and the load check says so.
- Juice Shop is deliberately vulnerable: some fixes (e.g. upgrading `jsonwebtoken`/`express-jwt`) break its training challenges.
  Validation reports exactly that, with the failing tests, instead of claiming success.
- Precision/recall are only meaningful with at least two independent scanners installed; the dashboard warns otherwise.
- Stretch goals (function-level reachability, automatic PRs, Sigstore/SLSA verification, policy-as-code, continuous monitoring) are not included.

### Publish approved fixes to GitHub

Sign in to GitHub with Git Credential Manager (`git credential-manager github login`) on the machine running the dashboard. The account needs permission to create private repositories, configure their Actions settings and push commits.

**Fetch and inspect** creates a private destination named `guardian-<source-name>-<source-hash>` under that account. Guardian disables Actions in the destination so imported workflows do not execute on push. After approval and successful validation, the first publication seeds `main` with the inspected base commit. Each validated run publishes its release candidate on a separate `guardian/…-release-candidate` branch. The verified report page links to the branch. If publishing fails, correct the reported issue and choose **Rebuild the verified report** to retry the same commit.
