"""Download Grype and Trivy (latest releases from GitHub) into tools/ for the benchmark. No PowerShell needed.

    python -m guardian.get_tools
"""
import io
import json
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
WIN = sys.platform.startswith("win")
ARCH = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
OS = "windows" if WIN else ("darwin" if sys.platform == "darwin" else "linux")
# asset name endings for each tool and platform
PATTERNS = {
    "grype": f"_{OS}_{ARCH}." + ("zip" if WIN else "tar.gz"),
    "trivy": {"windows": "_windows-64bit.zip", "linux": f"_Linux-{'ARM64' if ARCH == 'arm64' else '64bit'}.tar.gz",
              "darwin": f"_macOS-{'ARM64' if ARCH == 'arm64' else '64bit'}.tar.gz"}[OS],
}
REPOS = {"grype": "anchore/grype", "trivy": "aquasecurity/trivy"}


def get(url: str, accept: str = "application/octet-stream") -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "software-supply-chain-guardian", "Accept": accept})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def install(name: str):
    exe = TOOLS / (name + (".exe" if WIN else ""))
    if exe.exists():
        print(f"{name}: already in {exe}")
        return
    rel = json.loads(get(f"https://api.github.com/repos/{REPOS[name]}/releases/latest", "application/vnd.github+json"))
    asset = next((a for a in rel["assets"] if a["name"].endswith(PATTERNS[name])), None)
    if not asset:
        raise SystemExit(f"{name}: no release file ending in {PATTERNS[name]} in {rel['tag_name']}")
    print(f"{name}: downloading {asset['name']} ({asset['size'] // 1_000_000} MB) from release {rel['tag_name']}")
    data = get(asset["browser_download_url"])
    want = exe.name
    if asset["name"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            member = next(m for m in z.namelist() if Path(m).name == want)
            with z.open(member) as src, open(exe, "wb") as dst:
                shutil.copyfileobj(src, dst)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            member = next(m for m in t.getmembers() if Path(m.name).name == want and m.isfile())
            with t.extractfile(member) as src, open(exe, "wb") as dst:
                shutil.copyfileobj(src, dst)
    if not WIN:
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    print(f"{name}: installed {exe}")


if __name__ == "__main__":
    TOOLS.mkdir(exist_ok=True)
    for tool in ("grype", "trivy"):
        try:
            install(tool)
        except Exception as err:
            print(f"{tool}: failed - {type(err).__name__}: {err}")
    print("Done. Run the benchmark from the dashboard (Evaluate > Benchmark) or: python -m guardian.benchmark")
