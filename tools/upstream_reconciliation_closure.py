"""Validate the fixed M11.4 upstream-reconciliation authority."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "migration" / "m11_upstream_reconciliation.json"
EXPECTED_COMMITS = (
    "6c804e2b982e499d916668154c61f2650d13fa5b",
    "c8344b93cb225ce610f1f9af8ad5d35730bc4229",
    "891f667887015ad343c90cd2d6c40077921ec1cf",
    "1e9326b9f9447045b74fdd163c09af6ffc2bb2f9",
)


def validate_manifest(manifest: dict[str, object]) -> list[str]:
    """Return deterministic violations in an upstream reconciliation manifest."""
    errors: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("milestone") != "M11.4":
        errors.append("manifest identity or schema is invalid")
    if manifest.get("merge_policy") != "classify-and-port-without-merging-develop":
        errors.append("develop merge policy is invalid")
    if (
        manifest.get("last_informational_fetch_at") != "2026-09-21"
        or manifest.get("final_reconciliation_boundary") != "pending-claasp-4-freeze"
    ):
        errors.append("informational fetch or future CLAASP 4 freeze boundary is stale")
    records = manifest.get("records")
    if not isinstance(records, list):
        return errors + ["reconciliation records are missing"]
    commits = [record.get("commit") for record in records if isinstance(record, dict)]
    if tuple(commits) != EXPECTED_COMMITS:
        errors.append("upstream commit coverage or order is stale")
    if len(commits) != len(set(commits)):
        errors.append("upstream commit identities are duplicated")
    for record in records:
        if not isinstance(record, dict):
            errors.append("reconciliation record is not an object")
            continue
        commit = record.get("commit", "unknown")
        if record.get("disposition") not in {"ported", "superseded"}:
            errors.append(f"invalid disposition for {commit}")
        rationale = record.get("rationale")
        if not isinstance(rationale, str) or len(rationale.strip()) < 80:
            errors.append(f"missing substantive rationale for {commit}")
        evidence = record.get("evidence")
        if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
            errors.append(f"missing or duplicate evidence for {commit}")
            continue
        for value in evidence:
            if not isinstance(value, str) or not (ROOT / value).is_file():
                errors.append(f"missing evidence for {commit}: {value}")

    grain = ROOT / "src/claasp/primitives/permutations/grain_core.py"
    grain_text = grain.read_text(encoding="utf-8") if grain.is_file() else ""
    for required in ("self.state_bit_size = 160", "LFSR_CORE_POLY", "NFSR_CORE_POLY"):
        if required not in grain_text:
            errors.append(f"Grain v1 port invariant is missing: {required}")
    vectors = json.loads((ROOT / "migration/m10_9d7_fixed_vectors.json").read_text())
    grain_vectors = [record for record in vectors if record.get("class") == "GrainCore"]
    if len(grain_vectors) != 1 or grain_vectors[0].get("claim") != "specification-fixed-vector":
        errors.append("Grain v1 specification-vector authority is stale")
    elif len(grain_vectors[0].get("vectors", ())) != 2:
        errors.append("Grain v1 must retain both official vector cases")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("pass --check")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = validate_manifest(manifest)
    if errors:
        print("\n".join(errors))
        return 1
    records = manifest["records"]
    counts = {
        name: sum(record["disposition"] == name for record in records)
        for name in ("ported", "superseded")
    }
    print(
        "M11.4 upstream reconciliation passes: "
        f"{len(records)} commits, {counts['ported']} ported, {counts['superseded']} superseded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
