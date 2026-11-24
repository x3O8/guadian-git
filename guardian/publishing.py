"""Publish dashboard imports to private, source-specific GitHub repositories."""
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

from guardian.repo_fetch import parse_github_url


class PublishError(RuntimeError):
    pass


def git(repo, *args):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"})
    if proc.returncode:
        raise PublishError(f"Git {args[0]} failed. Check GitHub access and retry.")
    return proc.stdout.strip()


def credential():
    proc = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"})
    token = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line).get("password")
    if proc.returncode or not token:
        raise PublishError("Sign in with git credential-manager github login, then retry.")
    return token


def api(token, path, method="GET", data=None, missing_ok=False):
    request = urllib.request.Request("https://api.github.com" + path, method=method,
                                     data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "User-Agent": "Guardian",
                                              "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as err:
        if missing_ok and err.code == 404:
            return None
        raise PublishError(f"GitHub returned HTTP {err.code} for {method} {path}. Check account permissions and retry.") from None


def destination(repo, source):
    owner, name = parse_github_url(source)
    source_id = f"{owner}/{name}".lower()
    if git(repo, "remote", "get-url", "origin").lower().removesuffix(".git") != "https://github.com/" + source_id:
        raise PublishError("The source link does not match this checkout.")
    digest = hashlib.sha256(source_id.encode()).hexdigest()[:12]
    slug = f"guardian-{name.lower()[:65]}-{digest}"
    marker = f"Guardian validated fixes for https://github.com/{source_id}"
    token = credential()
    account = api(token, "/user")["login"]
    path = f"/repos/{account}/{slug}"
    record = api(token, path, missing_ok=True)
    if record is None:
        try:
            record = api(token, "/user/repos", "POST", {"name": slug, "private": True, "description": marker})
        except PublishError:
            record = api(token, path, missing_ok=True)
            if record is None:
                raise
    if not record["private"] or record["description"] != marker or record["full_name"].lower() == source_id:
        raise PublishError("The destination name is already in use by a different repository.")
    pinned = config(repo, "destination")
    if pinned and pinned != str(record["id"]):
        raise PublishError("The signed-in account or destination repository has changed.")
    git(repo, "config", "--local", "guardian.destination", str(record["id"]))
    api(token, path + "/actions/permissions", "PUT", {"enabled": False})
    return record["html_url"]


def config(repo, key):
    return git(repo, "config", "--local", "--default", "", "--get", "guardian." + key)


def publish(repo, source, candidate, base):
    url = destination(repo, source)
    commit = candidate["commit"]
    branch = candidate["branch"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[a-f0-9]{40}", base):
        raise PublishError("Missing validated Git commit.")
    if not branch.startswith("guardian/") or git(repo, "rev-parse", "refs/heads/" + branch) != commit:
        raise PublishError("The validated branch no longer matches the recorded commit.")
    if git(repo, "rev-parse", "--is-shallow-repository") == "true":
        git(repo, "fetch", "--unshallow", "--no-tags", "origin")
    remote = url + ".git"
    if not git(repo, "ls-remote", "--heads", remote, "refs/heads/main"):
        git(repo, "push", "--force-with-lease=refs/heads/main:", remote, base + ":refs/heads/main")
    ref = "refs/heads/" + branch
    git(repo, "push", "--force-with-lease=" + ref + ":", remote, commit + ":" + ref)
    return url + "/tree/" + branch
