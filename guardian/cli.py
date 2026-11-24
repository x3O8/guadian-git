import argparse
import sys
from pathlib import Path

from guardian.repo_fetch import FetchError, fetch, out_dir_for
from guardian.workflow import run


def main():
    sys.stdout.reconfigure(errors="replace")  # Windows consoles can't print every character
    p = argparse.ArgumentParser(description="Software Supply Chain Guardian — Day 1 scan")
    p.add_argument("--repo", default="target/juice-shop")
    p.add_argument("--github", help="public GitHub URL to fetch into target/ and scan (overrides --repo)")
    p.add_argument("--refresh", action="store_true", help="re-clone the GitHub repo even if present")
    p.add_argument("--out", default=None, help="output folder (default: reports/<repo name>)")
    p.add_argument("--base-ref", default="HEAD", help="git ref used as the trusted baseline")
    p.add_argument("--scanner", default="auto", choices=["auto", "osv", "npm-audit"])
    args = p.parse_args()

    repo = args.repo
    if args.github:
        try:
            repo = str(fetch(args.github, args.refresh, log=lambda m: print(f"[fetch  ] {m}")))
        except FetchError as err:
            print(f"[error  ] {err}")
            sys.exit(2)
    out = args.out or str(out_dir_for(Path(repo).resolve()))
    print(f"[info   ] scanning {repo} -> {out}")
    state = run(repo, out, args.base_ref, args.scanner)
    for entry in state["log"]:
        print(f"[{entry.status:7}] {entry.agent}: {entry.message}")
    if state.get("report"):
        print("\n" + state["report"]["interpretation"]["text"])
    sys.exit(1 if state["errors"] else 0)


if __name__ == "__main__":
    main()
