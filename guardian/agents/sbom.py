import json
import os
import shutil
import subprocess
from pathlib import Path

from guardian.models import Inventory, SbomSummary

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
SYFT_EXCLUDES = ["./frontend/**", "./test/**", "./node_modules/**"]


def find_tool(name: str):
    for candidate in (TOOLS_DIR / name, TOOLS_DIR / f"{name}.exe"):
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)  # also resolves npm.cmd / npx.cmd on Windows


def run_syft(repo: Path, out_file: Path, inv: Inventory) -> str:
    syft = find_tool("syft")
    if not syft:
        raise FileNotFoundError("syft")
    cmd = [syft, "scan", f"dir:{repo}", "-q", "--source-name", inv.app_name or repo.name,
           "-o", f"cyclonedx-json={out_file}"]
    if inv.app_version:
        cmd += ["--source-version", inv.app_version]
    for ex in SYFT_EXCLUDES:
        cmd += ["--exclude", ex]
    env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}
    subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, env=env)
    return "syft"


def run_cyclonedx_npm(repo: Path, out_file: Path) -> str:
    cmd = [find_tool("npx") or "npx", "--yes", "@cyclonedx/cyclonedx-npm", "--package-lock-only", "--omit", "dev",
           "--output-format", "JSON", "--output-file", str(out_file)]
    subprocess.run(cmd, cwd=repo, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    return "cyclonedx-npm"


def generate_sbom(repo: Path, out_dir: Path, inv: Inventory) -> SbomSummary:
    out_file = out_dir / f"{repo.name}-sbom.json"
    try:
        tool = run_syft(repo, out_file, inv)
    except (FileNotFoundError, subprocess.CalledProcessError) as err:
        print(f"[sbom] syft unavailable/failed ({err}); falling back to cyclonedx-npm")
        tool = run_cyclonedx_npm(repo, out_file)
    return summarize(out_file, tool, inv)


def summarize(sbom_file: Path, tool: str, inv: Inventory) -> SbomSummary:
    bom = json.loads(sbom_file.read_text(encoding="utf-8"))
    comps = bom.get("components", [])
    npm = [c for c in comps if c.get("purl", "").startswith("pkg:npm/")]
    sbom_keys = {(full_name(c), c.get("version")) for c in npm}
    inv_keys = {(c.name, c.version) for c in inv.npm()}
    prod_keys = {(c.name, c.version) for c in inv.npm() if c.scope != "dev"}
    return SbomSummary(
        path=str(sbom_file), tool=tool, format=bom.get("bomFormat", "unknown"),
        spec_version=bom.get("specVersion", "unknown"), component_count=len(comps),
        npm_component_count=len(npm), matched_inventory=len(sbom_keys & inv_keys),
        sbom_only=sorted(f"{n}@{v}" for n, v in sbom_keys - inv_keys),
        note=(f"SBOM lists shipped (non-dev) npm packages. Inventory has {len(prod_keys)} unique "
              f"non-dev name@version pairs; {len(sbom_keys & prod_keys)} match the SBOM."),
    )


def full_name(c: dict) -> str:
    group = c.get("group")
    return f"{group}/{c['name']}" if group else c["name"]
