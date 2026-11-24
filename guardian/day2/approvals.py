"""Human in the loop: nothing is changed until a named person decides.

Decisions per action: approve (validate it in the sandbox), reject, accept-risk (with a justification and
review date), or escalate (send to security review). Each decision is tied to the action's content hash:
if the plan is regenerated and the action's changes differ, the old decision no longer applies and the
action needs a fresh decision. Every decision is written to the hash-chained audit log.
"""
from pathlib import Path

from guardian.day2.common import audit, day2_dir, now, read_json, write_json
from guardian.models import Decision

CHOICES = {
    "approve": "Approve: apply in the sandbox, build, test and rescan",
    "reject": "Reject: do not apply",
    "accept-risk": "Accept the risk for now (needs a reason and a review date)",
    "escalate": "Escalate to security review",
}


def load_plan(out: Path) -> dict:
    return read_json(day2_dir(out) / "remediation_plan.json", {"actions": []})


def load_decisions(out: Path) -> dict:
    return read_json(day2_dir(out) / "decisions.json", {})


def current(out: Path) -> dict:
    """{action_id: decision} for decisions that still match an action's current content.
    Decisions are stored by the action's content hash, so re-running the plan keeps them only if the
    change itself is identical (ids may be renumbered)."""
    stored = load_decisions(out)
    valid = {}
    for a in load_plan(out)["actions"]:
        d = stored.get(a["hash"])
        if d:
            valid[a["id"]] = {**d, "action_id": a["id"]}
    return valid


def decide(out: Path, action_id: str, decision: str, reviewer: str, comment: str = "", expires: str = None) -> dict:
    if decision not in CHOICES:
        raise ValueError(f"decision must be one of {', '.join(CHOICES)}")
    reviewer = (reviewer or "").strip()
    if not reviewer:
        raise ValueError("A reviewer name is required: decisions must be attributable to a person.")
    if decision in ("reject", "accept-risk", "escalate") and not (comment or "").strip():
        raise ValueError("Please give a reason for rejecting, accepting or escalating.")
    if decision == "accept-risk" and not expires:
        raise ValueError("Accepted risks need a review date.")
    plan = {a["id"]: a for a in load_plan(out)["actions"]}
    a = plan.get(action_id)
    if not a:
        raise ValueError(f"Unknown action {action_id}")
    if decision == "approve" and not a["auto_applicable"]:
        raise ValueError(f"{action_id} has no automatic change to validate. Choose accept-risk or escalate.")
    d = Decision(action_id=action_id, decision=decision, reviewer=reviewer, comment=comment.strip(),
                 expires=expires, at=now(), plan_hash=a["hash"]).model_dump()
    all_d = load_decisions(out)
    all_d[a["hash"]] = d
    write_json(day2_dir(out) / "decisions.json", all_d)
    audit(out, f"human:{reviewer}", "decision", {"action": action_id, "title": a["title"], "decision": decision,
                                                  "comment": d["comment"], "expires": expires, "action_hash": a["hash"]})
    return d


def clear(out: Path, action_id: str, reviewer: str):
    all_d = load_decisions(out)
    a = {x["id"]: x for x in load_plan(out)["actions"]}.get(action_id)
    if a and a["hash"] in all_d:
        old = all_d.pop(a["hash"])
        write_json(day2_dir(out) / "decisions.json", all_d)
        audit(out, f"human:{reviewer or 'unknown'}", "decision-withdrawn", {"action": action_id, "was": old["decision"]})


def approved_actions(out: Path) -> list[dict]:
    dec = current(out)
    return [a for a in load_plan(out)["actions"] if dec.get(a["id"], {}).get("decision") == "approve" and a["auto_applicable"]]


def summary(out: Path) -> dict:
    plan, dec = load_plan(out)["actions"], current(out)
    counts = {k: 0 for k in CHOICES}
    for d in dec.values():
        counts[d["decision"]] += 1
    return {"actions": len(plan), "decided": len(dec), "pending": len(plan) - len(dec), **counts}
