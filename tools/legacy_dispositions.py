"""Validate reviewed semantic replacements without inferring parity from file existence."""

from __future__ import annotations

import argparse
import ast
import json
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
    return {
        "reviewed_supersede_decisions": len(records),
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
