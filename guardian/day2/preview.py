"""Local Docker previews of the exact commit that passed Guardian validation."""
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from guardian.day2 import approvals
from guardian.day2.common import day2_dir, read_json


def command(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=300, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-1500:] or f"{args[0]} failed")
    return result.stdout.decode(errors="replace").strip()


def identity(repo, commit):
    return hashlib.sha256(f"{repo.resolve()}:{commit}".encode()).hexdigest()


def container_id(key):
    return command("docker", "ps", "-aq", "--filter", f"label=guardian.preview={key}")


def stop(key):
    container = container_id(key)
    if container:
        command("docker", "rm", "-f", container)


def launch(repo, out, displayed_commit):
    latest = read_json(day2_dir(out) / "validation_latest.json", {})
    candidate = latest.get("combined") or {}
    commit = candidate.get("commit")
    actions = set(candidate.get("actions") or [])
    approved = {action["id"] for action in approvals.approved_actions(out)}
    if (commit != displayed_commit or not commit or not candidate.get("verdict", "").startswith("Verified")
            or not actions or not actions <= approved):
        raise ValueError("Refresh the report and validate the currently approved fixes.")
    ref = "refs/heads/" + candidate["branch"]
    if command("git", "-C", str(repo), "rev-parse", "--verify", ref) != commit:
        raise ValueError("The release branch has moved. Validate it again before running.")
    scripts = json.loads(command("git", "-C", str(repo), "show", commit + ":package.json")).get("scripts", {})
    if scripts.get("start"):
        startup = "npm start"
    elif scripts.get("dev"):
        startup = "npm run dev"
        if "vite" in scripts["dev"]:
            startup += " -- --host 0.0.0.0 --port 3000 --strictPort"
    else:
        raise ValueError("The project needs an npm start or dev script to run a preview.")
    if not shutil.which("docker"):
        raise ValueError("Install and start Docker Desktop to run the preview.")
    key = identity(repo, commit)
    container = container_id(key)
    if container and command("docker", "inspect", "-f", "{{.State.Status}}", container) == "exited":
        stop(key)
        container = None
    if not container:
        container = command("docker", "create", "--name", "guardian-preview-" + key[:24],
                            "--label", "guardian.preview=" + key, "--user", "node",
                            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                            "-p", "127.0.0.1::3000", "-e", "PORT=3000", "-e", "HOST=0.0.0.0",
                            "-w", "/app", "node:24-bookworm-slim", "sh", "-ec",
                            "mkdir /tmp/project && cp -R /app/. /tmp/project/ && cd /tmp/project && "
                            "npm ci --no-audit --no-fund && " + startup)
        try:
            with tempfile.TemporaryFile() as archive:
                subprocess.run(["git", "-C", str(repo), "archive", commit], stdout=archive, check=True, timeout=90)
                archive.seek(0)
                command("docker", "cp", "-", container + ":/app", stdin=archive)
            command("docker", "start", container)
        except Exception:
            command("docker", "rm", "-f", container)
            raise
    binding = command("docker", "port", container, "3000/tcp")
    url = "http://" + binding
    for _ in range(90):
        try:
            with urllib.request.urlopen(url, timeout=2):
                return url
        except (OSError, urllib.error.URLError):
            if command("docker", "inspect", "-f", "{{.State.Running}}", container) != "true":
                logs = subprocess.run(["docker", "logs", "--tail", "15", container], capture_output=True, timeout=15)
                raise RuntimeError((logs.stdout + logs.stderr).decode(errors="replace")[-1500:])
            time.sleep(1)
    raise ValueError("The app has not answered on port 3000 yet. Retry after installation, or stop the preview.")
