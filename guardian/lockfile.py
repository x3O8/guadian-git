import json
from pathlib import Path

DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


def load_lock(repo: Path) -> dict:
    lock_path = repo / "package-lock.json"
    if not lock_path.exists():
        raise FileNotFoundError(
            f"{lock_path} not found. Generate it with: "
            "npm install --package-lock-only --ignore-scripts --package-lock=true"
        )
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion", 1) < 2 or "packages" not in lock:
        raise ValueError("Only package-lock.json v2/v3 (with 'packages') is supported")
    return lock


def name_from_path(lock_path: str) -> str:
    return lock_path.rsplit("node_modules/", 1)[-1]


def resolve(packages: dict, from_path: str, dep_name: str):
    """Node resolution: look in from_path/node_modules, then walk up to the root."""
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{dep_name}" if base else f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def edges(packages: dict):
    """Yield (parent_path, child_path_or_None, dep_name, range, field)."""
    for path, meta in packages.items():
        if meta.get("link"):
            continue
        for field in DEP_FIELDS:
            for dep, rng in (meta.get(field) or {}).items():
                yield path, resolve(packages, path, dep), dep, rng, field
