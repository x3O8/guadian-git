from typing import Optional
from pydantic import BaseModel, Field


class Component(BaseModel):
    name: str
    version: str
    ecosystem: str  # npm, docker, github-actions
    direct: bool = False
    scope: str = "prod"  # prod, dev, optional
    lock_path: str = ""  # node_modules/... path in package-lock.json
    declared_range: Optional[str] = None
    pinning: str = "exact"  # exact, range, tag, digest, sha, branch
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    has_install_script: bool = False
    license: Optional[str] = None
    source_file: str = ""


class Manifest(BaseModel):
    path: str
    kind: str  # manifest, lockfile, container, ci
    ecosystem: str


class Inventory(BaseModel):
    repo: str
    app_name: str
    app_version: str
    commit: Optional[str] = None
    manifests: list[Manifest] = []
    components: list[Component] = []
    declared_not_locked: list[str] = []

    def npm(self):
        return [c for c in self.components if c.ecosystem == "npm"]


class SbomSummary(BaseModel):
    path: str
    tool: str
    format: str
    spec_version: str
    component_count: int
    npm_component_count: int
    matched_inventory: int
    sbom_only: list[str] = []
    note: str = ""


class GraphSummary(BaseModel):
    json_path: str
    html_path: str
    nodes: int
    edges: int
    direct: int
    transitive: int
    unresolved_edges: list[str] = []


class Vulnerability(BaseModel):
    id: str
    aliases: list[str] = []
    package: str
    installed_version: str
    severity: str
    affected_range: Optional[str] = None
    fixed_version: Optional[str] = None
    fixed_version_source: Optional[str] = None
    title: str = ""
    direct: bool
    scope: str
    dependency_path: list[str] = []
    introduced_via: list[str] = []
    evidence_source: str
    reference: Optional[str] = None
    cvss: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: list[str] = []


class SuspiciousFinding(BaseModel):
    id: str
    category: str
    severity: str
    file: str
    title: str
    before: Optional[str] = None
    after: Optional[str] = None
    why_suspicious: str
    evidence: dict = Field(default_factory=dict)
    kind: str = "change"  # change (git diff) or baseline (static posture)
    remediation: str = ""


class AgentLog(BaseModel):
    agent: str
    status: str
    message: str


# ---------------- Day 2 ----------------
class FactorScore(BaseModel):
    factor: str            # severity, exploitability, reachability, exposure
    points: float
    max_points: float
    reason: str            # one plain sentence built from evidence


class RiskItem(BaseModel):
    id: str                # RISK-001
    kind: str              # vulnerability or supply-chain
    subject: str           # package@version, or file for supply-chain items
    package: Optional[str] = None
    version: Optional[str] = None
    lock_path: Optional[str] = None
    advisories: list[str] = []
    worst_severity: str
    score: float           # 0-100
    tier: str              # Critical, High, Medium, Low
    factors: list[FactorScore]
    confidence: float      # 0-1
    confidence_label: str
    confidence_reasons: list[str]
    evidence: dict = Field(default_factory=dict)
    reasoning: str = ""    # why it is severe (LLM or rule-based)
    reasoning_source: str = ""


class Investigation(BaseModel):
    id: str                # INV-001
    category: str
    title: str
    subject: str
    verdict: str           # Suspicious, Needs review, Expected
    severity: str
    verified_evidence: list[dict]   # {"fact": ..., "source": ...}
    inference: str = ""
    inference_source: str = ""
    remedy: str = ""
    day1_ref: Optional[str] = None


class Change(BaseModel):
    file: str
    op: str                # set-dependency, add-override, remove-dependency, set-json, replace-text
    target: str            # package name, json key or text to find
    value: Optional[str] = None
    section: Optional[str] = None


class RemediationAction(BaseModel):
    id: str                # ACT-001
    type: str              # upgrade, upgrade-parent, pin-override, replace-remove, update-base-image, pin-action, block, escalate, harden-config
    title: str
    covers_packages: list[str] = []
    covers_risks: list[str] = []
    advisories_cleared: int = 0
    severity_cleared: dict = Field(default_factory=dict)
    changes: list[Change] = []
    auto_applicable: bool = False
    expected_risk_reduction: dict = Field(default_factory=dict)
    compatibility: dict = Field(default_factory=dict)
    rollback: str = ""
    rationale: str = ""
    rationale_source: str = ""
    priority: str = ""
    confidence: float = 0.0


class Decision(BaseModel):
    action_id: str
    decision: str          # approve, reject, accept-risk, escalate
    reviewer: str
    comment: str = ""
    expires: Optional[str] = None
    at: str
    plan_hash: str
