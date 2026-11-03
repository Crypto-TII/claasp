"""Validate reviewed semantic replacements without inferring parity from file existence."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate(root=ROOT):
    snapshot = json.loads((root / "tools/data/legacy_current_snapshot.json").read_text())
    frozen = json.loads((root / "tools/data/legacy_inventory.json").read_text())
    review = json.loads((root / "tools/data/legacy_disposition_review.json").read_text())
    expected = {row["path"] for row in frozen["records"] if row["disposition"] == "supersede"}
    records = {row["path"]: row for row in review["records"]}
    if len(records) != len(review["records"]) or set(records) != expected:
        raise ValueError("every historical supersede decision needs exactly one explicit review")
    if review["source_commit"] != snapshot["source_commit"]:
        raise ValueError("disposition review uses a different legacy snapshot")
    hashes = {row["path"]: row["sha256"] for row in snapshot["python_files"]}
    for path, row in records.items():
        if row["sha256"] != hashes[path]:
            raise ValueError(f"review is stale for changed legacy source: {path}")
        if row["decision"] != "typed_semantic_replacement" or row["scientific_capability_removed"]:
            raise ValueError(f"new deletion or decision needs explicit review: {path}")
        if row["review_group"] not in review["groups"]:
            raise ValueError(f"missing semantic review group: {path}")
    tests = set()
    for name, group in review["groups"].items():
        if not group["replacement_contract"] or not group["evidence_files"]:
            raise ValueError(f"empty replacement contract: {name}")
        for file in group["evidence_files"]:
            path = root / file
            if not path.is_file():
                raise ValueError(f"missing executable replacement evidence: {file}")
            tree = ast.parse(path.read_text())
            assertions = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
                and node.name.startswith("test_")
                and any(isinstance(item, ast.Assert) for item in ast.walk(node))
            ]
            if not assertions:
                raise ValueError(f"evidence has no numerical/contract test assertions: {file}")
            tests.add(file)
    removed = json.loads((root / "tools/data/legacy_removal_review.json").read_text())
    expected_removed = {row["path"] for row in frozen["records"] if row["disposition"] == "remove"}
    if {row["path"] for row in removed["records"]} != expected_removed or len(
        removed["records"]
    ) != len(expected_removed):
        raise ValueError("every historical remove decision needs one explicit review")
    if removed["source_commit"] != snapshot["source_commit"]:
        raise ValueError("removal review snapshot differs")
    for row in removed["records"]:
        if (
            row["sha256"] != hashes[row["path"]]
            or row["capability_removal"]
            or row["reviewed_disposition"] != "architecture_replacement"
        ):
            raise ValueError(f"unreviewed removal: {row['path']}")
        if (
            not row["replacement_contract"]
            or not row["evidence"]
            or any(not (root / file).is_file() for file in row["evidence"])
        ):
            raise ValueError(f"missing removal replacement evidence: {row['path']}")
    resources = json.loads((root / "tools/data/legacy_resource_review.json").read_text())
    expected_resources = {row["path"]: row["sha256"] for row in snapshot["resources"]}
    if (
        resources["source_commit"] != snapshot["source_commit"]
        or len(resources["records"]) != len(expected_resources)
        or {row["path"]: row["sha256"] for row in resources["records"]} != expected_resources
    ):
        raise ValueError("resource review does not exactly cover the pinned snapshot")
    for group in resources["groups"].values():
        if (
            not group["contract"]
            or not group["evidence"]
            or any(not (root / file).is_file() for file in group["evidence"])
        ):
            raise ValueError("missing resource replacement evidence")
    for row in resources["records"]:
        if row["review_group"] not in resources["groups"]:
            raise ValueError(f"unreviewed resource: {row['path']}")
        if "v5_path" in row:
            path = root / row["v5_path"]
            value = (
                b"SYMLINK\0" + os.readlink(path).encode()
                if path.is_symlink()
                else path.read_bytes()
            )
            if hashlib.sha256(value).hexdigest() != row["sha256"]:
                raise ValueError(f"preserved resource changed: {row['path']}")
    return {
        "reviewed_supersede_decisions": len(records),
        "reviewed_architecture_removals": len(removed["records"]),
        "reviewed_resources": len(resources["records"]),
        "semantic_groups": len(review["groups"]),
        "assertion_bearing_test_files": len(tests),
        "claim": "reviewed scoped replacement contracts; test execution is enforced separately by the unit and external CI jobs",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="validate the committed reviewed decisions"
    )
    parser.parse_args()
    print(json.dumps(validate(), indent=2))


if __name__ == "__main__":
    main()
