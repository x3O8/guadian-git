"""Day 2 command line.

    python -m guardian.day2 plan      [--repo target/juice-shop] [--no-llm]   agents 6-7, stops at the approval gate
    python -m guardian.day2 review    [--reviewer NAME]                       decide each action in the terminal
    python -m guardian.day2 validate  [--mode each|together] [--no-tests]     agent 8 for approved actions
    python -m guardian.day2 report                                            rebuild the verified report only
    python -m guardian.day2 status                                            show plan, decisions and audit chain
    python -m guardian.day2 checkout  --reviewer NAME                         open the validated fix as its own folder
"""
import argparse
import sys
from datetime import date, timedelta
from pathlib import Path

from guardian.day2 import approvals, verify_report
from guardian.day2.common import verify_audit
from guardian.day2.workflow2 import run
from guardian.repo_fetch import out_dir_for


def review(out: Path, reviewer: str):
    plan = approvals.load_plan(out)["actions"]
    dec = approvals.current(out)
    reviewer = reviewer or input("Your name (recorded with every decision): ").strip()
    for a in plan:
        if a["id"] in dec:
            continue
        print("\n" + "=" * 78)
        print(f"{a['id']}  {a['title']}   [{a['priority']} priority, confidence {a['confidence']}]")
        for c in a["changes"]:
            print(f"   change: {c['file']}: {c['op']} {c['target']}" + (f" = {c['value']}" if c.get("value") else ""))
        print(f"   expected: {a['expected_risk_reduction'].get('statement', '')}")
        print(f"   compatibility ({a['compatibility'].get('level')}): {a['compatibility'].get('summary', '')}")
        print(f"   rollback: {a['rollback']}")
        opts = "[a]pprove  [r]eject  accept-ris[k]  [e]scalate  [s]kip  [q]uit" if a["auto_applicable"] else \
               "no automatic change:  [r]eject  accept-ris[k]  [e]scalate  [s]kip  [q]uit"
        ch = input(opts + " > ").strip().lower()[:1]
        if ch == "q":
            break
        m = {"a": "approve", "r": "reject", "k": "accept-risk", "e": "escalate"}.get(ch)
        if not m:
            continue
        comment = input("Reason / comment: ").strip() if m != "approve" else input("Comment (optional): ").strip()
        expires = None
        if m == "accept-risk":
            expires = input(f"Review by (YYYY-MM-DD) [{date.today() + timedelta(days=30)}]: ").strip() or str(date.today() + timedelta(days=30))
        try:
            approvals.decide(out, a["id"], m, reviewer, comment, expires)
            print(f"   recorded: {m} by {reviewer}")
        except ValueError as err:
            print(f"   not recorded: {err}")


def main():
    ap = argparse.ArgumentParser(description="Guardian Day 2: prioritise, investigate, remediate, approve, validate, report")
    ap.add_argument("command", choices=["plan", "review", "validate", "report", "status", "checkout"])
    ap.add_argument("--repo", default="target/juice-shop")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-llm", action="store_true", help="rule-based explanations only")
    ap.add_argument("--mode", default="each", choices=["each", "together"], help="validate each action alone first, or only together")
    ap.add_argument("--no-tests", action="store_true")
    ap.add_argument("--reviewer", default="")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    repo = Path(a.repo)
    out = Path(a.out) if a.out else out_dir_for(repo.resolve())
    if a.command == "plan":
        s = run(str(repo), str(out), "plan", use_llm=not a.no_llm)
        print(f"\nPlan written to {out / 'day2'}. Next: review it in the dashboard or run `python -m guardian.day2 review`.")
        sys.exit(1 if s.get("errors") else 0)
    if a.command == "review":
        review(out, a.reviewer)
        print("\n", approvals.summary(out))
    elif a.command == "validate":
        if not approvals.approved_actions(out):
            print("No approved actions. Approve at least one in the dashboard or with `python -m guardian.day2 review`.")
        s = run(str(repo), str(out), "validate", mode=a.mode, run_tests=not a.no_tests, use_llm=not a.no_llm)
        sys.exit(1 if s.get("errors") else 0)
    elif a.command == "report":
        r = verify_report.build(out, repo.resolve().name)
        print(f"Verified report: {out / 'day2' / 'verified_report.pdf'}  (confidence {r['summary']['final_confidence_label']})")
    elif a.command == "checkout":
        from guardian.day2 import final_output
        dest = final_output.check_out(out, a.reviewer or input("Your name: "))
        print(f"Release candidate checked out to {dest} (a git worktree; your original copy is untouched).")
    else:
        print(approvals.summary(out))
        print("audit:", verify_audit(out)[1])
        for x in approvals.load_plan(out)["actions"]:
            d = approvals.current(out).get(x["id"])
            print(f"{x['id']}  {(d['decision'] + ' by ' + d['reviewer']) if d else 'pending':28}  {x['title']}")


if __name__ == "__main__":
    main()
