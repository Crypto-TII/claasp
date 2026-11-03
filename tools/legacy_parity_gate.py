"""Check current-legacy provenance, inventory completeness and scoped evidence.

The frozen v4 inventory stays unchanged. This gate covers source discovery and
explicit delta evidence; it does not turn file existence into semantic parity.
Use --legacy-root with a checkout of develop to detect newly added or changed
legacy files. An intentional snapshot update requires reviewing their behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tools/data/legacy_current_snapshot.json"


def validate(root=ROOT, legacy_root=None):
    snapshot = json.loads((root / SNAPSHOT.relative_to(ROOT)).read_text())
    frozen = json.loads((root / "tools/data/legacy_inventory.json").read_text())
    current = {item["path"]: item for item in snapshot["python_files"]}
    if len(current) != len(snapshot["python_files"]):
        raise ValueError("duplicate snapshot Python paths")
    core = {path for path in current if path.startswith(("claasp/", "tests/"))}
    baseline = {item["path"] for item in frozen["records"]}
    deltas = {}
    # Catalogue records preserve the frozen schema; the other feature deltas
    # record pinned hashes and deliberately narrower semantic evidence.
    for path in sorted((root / "tools/data").glob("*inventory_delta.json")):
        data = json.loads(path.read_text())
        commit = data.get("source_commit") or data.get("source_snapshot", {}).get("commit")
        for item in data["records"]:
            name = item["path"]
            if name in deltas:
                raise ValueError(f"duplicate delta: {name}")
            if name not in current:
                raise ValueError(f"delta is outside current source: {name}")
            if item.get("sha256") and item["sha256"] != current[name]["sha256"]:
                raise ValueError(f"delta hash differs: {name}")
            if commit and commit != snapshot["source_commit"]:
                raise ValueError(f"delta commit differs: {path.name}")
            evidence = item.get("evidence") or item.get("tests")
            if not evidence or any(not (root / test).is_file() for test in evidence):
                raise ValueError(f"delta has no executable evidence: {name}")
            if not (root / item["v5_destination"]).is_file():
                raise ValueError(f"delta destination is missing: {name}")
            deltas[name] = item
    if core != baseline | set(deltas):
        raise ValueError(
            f"inventory mismatch: missing={sorted(core - baseline - set(deltas))}; obsolete={sorted((baseline | set(deltas)) - core)}"
        )
    if legacy_root is not None:
        legacy_root = Path(legacy_root)
        tracked_names = (
            subprocess.check_output(["git", "ls-files", "-z"], cwd=legacy_root).decode().split("\0")
        )
        tracked = {name for name in tracked_names if name}
        recorded = set(current) | {item["path"] for item in snapshot["resources"]}
        if tracked != recorded:
            raise ValueError(
                f"legacy file drift: added={sorted(tracked - recorded)}; removed={sorted(recorded - tracked)}"
            )
        for item in list(current.values()) + snapshot["resources"]:
            if (
                hashlib.sha256(
                    b"SYMLINK\0" + os.readlink(legacy_root / item["path"]).encode()
                    if (legacy_root / item["path"]).is_symlink()
                    else (legacy_root / item["path"]).read_bytes()
                ).hexdigest()
                != item["sha256"]
            ):
                raise ValueError(
                    f"legacy content changed: {item['path']}; review and update scoped evidence"
                )
    return {
        "python_files": len(current),
        "core_inventory_files": len(core),
        "delta_files": len(deltas),
        "resources": len(snapshot["resources"]),
        "scope": "provenance and delta evidence only; no blanket semantic-parity claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(legacy_root=args.legacy_root), indent=2))


if __name__ == "__main__":
    main()
