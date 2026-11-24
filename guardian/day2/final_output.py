"""The final output of Day 2: the validated fix as real git commits, packaged next to the report.

After validation, every fix that passed is committed together on the release-candidate branch
(guardian/<run>-release-candidate) inside the target repository's own git. Nothing is merged into your
branch. Dashboard imports publish a verified candidate to their dedicated GitHub repository. This module exports that result to reports/<repo>/day2/final/:

  release-candidate.patch          readable diff of every file the fixes changed (lockfile summarised)
  0001-Guardian-remediation.patch  `git format-patch` mail patch: `git am` replays the commit with its message
  package.json, package-lock.json  the fixed files exactly as committed
  FINAL.md                         branch, commit, what is in it, verdict, how to review, apply and roll back

and, on a person's request, checks the release candidate out into a separate folder (a git worktree), so
the fixed code can be opened and run without touching the original copy.
"""
import subprocess
import shutil
from guardian import publishing
from pathlib import Path

from guardian.day2.common import audit, day2_dir, read_json, run, tool


def _git(repo: Path, args: list):
    return run([tool("git"), "-C", str(repo), "-c", "core.longpaths=true"] + args, timeout=300)


def git_view(repo: Path) -> dict:
    """What the Guardian left in the target repository's git: its branches, approval tags, and the latest commit."""
    repo = Path(repo)
    fmt = "%(refname:short)|%(objectname:short)|%(committerdate:iso8601)|%(subject)"
    br = _git(repo, ["for-each-ref", "refs/heads/guardian", "--sort=-committerdate", f"--format={fmt}"])["stdout"]
    tg = _git(repo, ["for-each-ref", "refs/tags/guardian-approved", "--sort=-creatordate",
                     "--format=%(refname:short)|%(objectname:short)|%(taggername)|%(taggerdate:iso8601)|%(contents:subject)"])["stdout"]
    branches = [dict(zip(["branch", "commit", "date", "subject"], l.split("|", 3))) for l in br.splitlines() if l.strip()]
    tags = [dict(zip(["tag", "object", "tagger", "date", "message"], l.split("|", 4))) for l in tg.splitlines() if l.strip()]
    return {"branches": branches, "tags": tags}


def export(out: Path) -> dict | None:
    val = read_json(day2_dir(out) / "validation_latest.json")
    rc = (val or {}).get("combined") or {}
    if not rc.get("commit") or not rc.get("verdict", "").startswith("Verified"):
        return None
    repo = Path(val["repo"])
    final = day2_dir(out) / "final"
    if final.exists():
        shutil.rmtree(final)
    final.mkdir(parents=True)
    exists = _git(repo, ["cat-file", "-e", rc["commit"]])["code"] == 0
    files = {}
    if exists:
        changed = [l for l in _git(repo, ["diff", "--name-only", rc["snapshot"], rc["commit"]])["stdout"].splitlines() if l.strip()]
        for name in ("package.json", "package-lock.json"):
            r = _git(repo, ["show", f"{rc['commit']}:{name}"])
            if r["code"] == 0:
                (final / name).write_text(r["stdout"], encoding="utf-8")
                files[name] = True
        diff = _git(repo, ["diff", rc["snapshot"], rc["commit"], "--", ".", ":(exclude)package-lock.json"])["stdout"]
        lock = _git(repo, ["diff", "--stat", rc["snapshot"], rc["commit"], "--", "package-lock.json"])["stdout"]
        (final / "release-candidate.patch").write_text(diff + ("\n# package-lock.json (regenerated, see the file itself)\n# " +
                                                              lock.replace("\n", "\n# ") if lock else ""), encoding="utf-8")
        fp = _git(repo, ["format-patch", "--stdout", f"{rc['snapshot']}..{rc['commit']}"])
        (final / "0001-Guardian-remediation.patch").write_text(fp["stdout"], encoding="utf-8")
        log = _git(repo, ["log", "--format=commit %H%nAuthor: %an%nDate:   %ad%n%n%B", f"{rc['snapshot']}..{rc['commit']}"])["stdout"].strip()
    else:
        changed, log = [], "(commit no longer in the repository: re-run validation)"
        src = out / val["dir"] / "release-candidate" / "remediation.patch"
        if src.exists():
            shutil.copy2(src, final / "release-candidate.patch")
    plan = {a["id"]: a for a in read_json(day2_dir(out) / "remediation_plan.json", {"actions": []})["actions"]}
    dec = read_json(day2_dir(out) / "decisions.json", {})
    by_hash = {d.get("plan_hash"): d for d in dec.values()}
    d = rc.get("diff") or {}
    t = rc.get("tests") or {}
    rel = repo.name
    lines = [f"# Final output: validated remediation for {rel}", "",
             f"- Branch: `{rc['branch']}` in `target/{rel}`",
             f"- Approval tag: `{rc.get('tag') or 'none'}` (annotated, created in the approver's name)",
             f"- Commit: `{rc['commit']}` on top of the snapshot `{rc['snapshot'][:12]}` of base `{val['base_commit'][:12]}`",
             f"- Verdict: **{rc['verdict']}**: " + "; ".join(rc.get("reasons") or []),
             f"- Advisories {d.get('advisories_before')} -> {d.get('advisories_after')}; tests {t.get('passed')} passed, {t.get('failed')} failed",
             f"- SBOM components {d.get('sbom_components_before')} -> {d.get('sbom_components_after')}; "
             f"{len(d.get('new_vulnerabilities', []))} new advisories", "", "## Fixes in this commit", ""]
    for aid in rc["actions"]:
        a = plan.get(aid, {})
        who = by_hash.get(a.get("hash"), {})
        lines.append(f"- {aid} {a.get('title', '')} (approved by {who.get('reviewer', '?')} {who.get('at', '')[:16]})")
    lines += ["", "## Files changed", ""] + [f"- {c}" for c in changed] + ["", "## Commits", "", "```", log, "```", "",
              "## Review, apply, roll back (a person does this)", "", "```bat",
              f":: the branches and approval tags the Guardian created",
              f"git -C target\\{rel} branch --list \"guardian/*\" -v",
              f"git -C target\\{rel} tag -n9 --list \"guardian-approved/*\"",
              f":: the commit, with who approved it",
              f"git -C target\\{rel} log -1 {rc['branch']}",
              f"git -C target\\{rel} show --stat {rc['commit'][:12]}",
              f":: open the fixed code in its own folder, without touching your copy",
              f"git -C target\\{rel} worktree add ..\\{rel}-fixed {rc['branch']}",
              f":: apply to your own branch when you are satisfied",
              f"git -C target\\{rel} merge --no-ff {rc['branch']}",
              f":: or, in any clone of the project: git am 0001-Guardian-remediation.patch",
              f":: undo after merging",
              f"git -C target\\{rel} revert -m 1 HEAD", "```", "",
              "Juice Shop ignores package-lock.json in git; if `merge` complains that the untracked lockfile would be "
              "overwritten, delete target\\juice-shop\\package-lock.json first (the branch carries the new one)."]
    (final / "FINAL.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    info = {"branch": rc["branch"], "commit": rc["commit"], "snapshot": rc["snapshot"], "repo": str(repo), "tag": rc.get("tag"),
            "commit_log": log,
            "actions": rc["actions"], "files_changed": changed, "commit_exists": exists, "dir": final.relative_to(out).as_posix(),
            "worktree": None}
    prev = read_json(day2_dir(out) / "final_output.json") or {}
    if exists:
        try:
            source = publishing.config(repo, "source")
            if source:
                if prev.get("commit") == rc["commit"] and prev.get("published_url"):
                    info["published_url"] = prev["published_url"]
                else:
                    info["published_url"] = publishing.publish(repo, source, rc, val["base_commit"])
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as err:
            info["publish_error"] = str(err)
    if info.get("published_url") or info.get("publish_error"):
        with (final / "FINAL.md").open("a", encoding="utf-8") as summary:
            summary.write("\nGitHub publication: " + (info.get("published_url") or info["publish_error"]) + "\n")
    if prev.get("commit") == rc["commit"] and prev.get("worktree") and Path(prev["worktree"]).exists():
        info["worktree"] = prev["worktree"]
    from guardian.day2.common import write_json
    write_json(day2_dir(out) / "final_output.json", info)
    return info


def check_out(out: Path, reviewer: str) -> Path:
    """On a person's request: the release candidate as a normal folder next to the original (git worktree)."""
    if not (reviewer or "").strip():
        raise ValueError("A reviewer name is required.")
    info = read_json(day2_dir(out) / "final_output.json")
    if not info or not info.get("commit_exists"):
        raise ValueError("No validated release candidate to check out. Run validation first.")
    repo = Path(info["repo"])
    dest = repo.parent / f"{repo.name}-fixed"
    if dest.exists():
        _git(repo, ["worktree", "remove", "--force", str(dest)])
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
    r = _git(repo, ["worktree", "add", "-f", str(dest), info["branch"]])
    if r["code"]:
        raise RuntimeError(r["stderr"][-300:])
    info["worktree"] = str(dest)
    from guardian.day2.common import write_json
    write_json(day2_dir(out) / "final_output.json", info)
    audit(out, f"human:{reviewer.strip()}", "release-candidate-checked-out", {"branch": info["branch"], "commit": info["commit"], "folder": str(dest)})
    return dest
