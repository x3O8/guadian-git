"""Shared helpers for Day 2: where files live, loading Day 1 evidence, and the audit trail."""
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "sandbox"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def day2_dir(out: Path) -> Path:
    d = Path(out) / "day2"
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_json(path: Path, default=None):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def write_json(path: Path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_day1(out: Path) -> dict:
    """Everything Day 1 wrote, in one dict. Raises if Day 1 hasn't run."""
    out = Path(out)
    report = read_json(out / "evidence_report.json")
    if not report:
        raise RuntimeError(f"No Day 1 results in {out}. Run the Day 1 inspection first.")
    return {
        "out": out,
        "report": report,
        "inventory": read_json(out / "inventory.json", {}),
        "deps": (read_json(out / "dependency_inventory.json", {}) or {}).get("dependencies", []),
        "vulns": read_json(out / "vulnerability_findings.json", {"findings": [], "scanner": None}),
        "suspicious": read_json(out / "suspicious_changes.json", {"findings": [], "base_ref": "HEAD"}),
        "recs": read_json(out / "fix_recommendations.json", []),
        "graph": read_json(out / "dependency_graph.json", {"nodes": [], "edges": []}),
    }


def tool(name: str):
    """Resolve npm/npx/git to a full path (npm.cmd on Windows)."""
    return shutil.which(name) or name


def run(cmd: list, cwd=None, timeout=900, env_extra: dict = None) -> dict:
    """Run a command, never through a shell. Returns a small result record for the evidence."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "npm_config_fund": "false", "npm_config_audit": "false",
           "npm_config_update_notifier": "false", "CI": "true", **(env_extra or {})}
    start = datetime.now()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=env)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        code, stdout, stderr = -1, (e.stdout or "") if isinstance(e.stdout, str) else "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        code, stdout, stderr = -2, "", str(e)
    return {"cmd": " ".join(str(c) for c in cmd), "code": code, "seconds": round((datetime.now() - start).total_seconds(), 1),
            "stdout": stdout[-20000:], "stderr": stderr[-8000:]}


# ---------------- audit trail (append-only, hash-chained) ----------------
def _hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def audit(out: Path, actor: str, event: str, details: dict = None) -> dict:
    """Append one event. Each entry carries the previous entry's hash, so editing history breaks the chain."""
    path = day2_dir(out) / "audit_log.jsonl"
    prev = "0" * 64
    seq = 0
    if path.exists():
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev, seq = last["hash"], last["seq"] + 1
    entry = {"seq": seq, "at": now(), "actor": actor, "event": event, "details": details or {}, "prev_hash": prev}
    entry["hash"] = _hash(entry)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")
    return entry


def read_audit(out: Path) -> list[dict]:
    path = day2_dir(out) / "audit_log.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def verify_audit(out: Path) -> tuple[bool, str]:
    entries = read_audit(out)
    prev = "0" * 64
    for e in entries:
        if e.get("prev_hash") != prev or _hash(e) != e.get("hash"):
            return False, f"chain broken at entry {e.get('seq')} ({e.get('event')})"
        prev = e["hash"]
    return True, f"{len(entries)} entries, chain intact"
