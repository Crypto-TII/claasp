"""Generate and validate the final bidirectional CLAASP migration matrix."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "migration/legacy_inventory.json"
MATRIX = ROOT / "migration/m11a_bidirectional_migration.json"
SUMMARY = ROOT / "docs/final_migration_audit.md"

NEW_V5_RATIONALES = {
    "analysis": "New typed analysis composition, evidence, and result contracts separate claims from execution.",
    "annotations": "New immutable graph-annotation and execution-trace architecture has no single legacy file predecessor.",
    "catalogue": "New immutable generated catalogue and query architecture replaces cross-cutting legacy discovery behavior.",
    "components": "New typed component hierarchy and shared semantic contracts consolidate many legacy backend-bearing classes.",
    "composites": "New reusable composite-block authoring layer has no direct legacy module predecessor.",
    "domains": "New explicit Bit, Word, and finite-field domain model replaces implicit backend-specific types.",
    "drivers": "New bounded typed external-driver boundary separates tools and optional dependencies from core semantics.",
    "graph": "New immutable typed graph, binding, round, metadata, and realization architecture is v5 infrastructure.",
    "parameters": "New validated parameter-resource API makes packaged constants explicit and dependency-free.",
    "presentation": "New pure presentation-data, formatting, export, and optional-rendering boundary is v5 infrastructure.",
    "primitives": "New v5 primitive support, export, realization, or packaged-data artifact has reviewed catalogue ownership.",
    "representations": "New typed lowering and execution architecture consolidates multiple mutable legacy model backends.",
    "semantics": "New backend-neutral semantic registry and immutable cryptanalytic evidence model is v5 infrastructure.",
    "serialization": "New canonical serialization architecture has no safe legacy serialization predecessor.",
    "transformations": "New immutable graph transformation architecture replaces mutation-oriented legacy helpers.",
    "utils": "New dependency-free validated utility contract consolidates cross-cutting legacy helpers.",
    "root": "New v5 package boundary, provenance, encoding, or public export authority has no single legacy predecessor.",
}


def release_files() -> list[str]:
    """Return deterministic package-relative paths for every shipped artifact."""
    package = ROOT / "src/claasp"
    return sorted(
        path.relative_to(ROOT).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    )


def _destination_paths(value: str) -> tuple[str, ...]:
    paths = []
    for raw in value.split(";"):
        destination = raw.strip()
        if destination.startswith("claasp/"):
            destination = "src/" + destination
        if destination.startswith("src/claasp"):
            paths.append(destination)
    return tuple(paths)


def _covers(destination: str, artifact: str) -> bool:
    path = ROOT / destination
    return (
        artifact == destination
        if path.is_file()
        else artifact.startswith(destination.rstrip("/") + "/")
    )


def _legacy_rationale(record: dict[str, Any], destinations: tuple[str, ...]) -> str:
    rationale = str(record.get("rationale", "")).strip()
    if rationale:
        return rationale
    responsibility = str(record.get("responsibility", "")).strip() or record["path"]
    owner = record.get("milestone_owner") or "the reviewed migration inventory"
    status = str(record["status"]).replace("-", " ")
    if record["kind"] == "test":
        return (
            f"Legacy regression coverage for {responsibility} is {status} under {owner}; "
            "the linked v5 fixed-vector, semantic, and catalogue evidence replaces the "
            "legacy test-module shape."
        )
    if destinations:
        return (
            f"The {responsibility} surface is {status} under {owner}; its reviewed behavior "
            "moves to the typed destination(s) while the legacy mutable/package-specific API "
            "shape is not retained."
        )
    return (
        f"The {responsibility} record is {status} under {owner}; its reviewed behavior is "
        "accounted for by fixed migration evidence rather than a separately shipped v5 source "
        "artifact."
    )


def build_matrix() -> dict[str, Any]:
    """Build the deterministic legacy-to-v5 and v5-to-legacy authority."""
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    legacy_records = []
    destinations_by_legacy: dict[str, tuple[str, ...]] = {}
    for record in inventory["records"]:
        destinations = _destination_paths(record["v5_destination"])
        public_entry_points = list(dict.fromkeys(record.get("public_entry_points", [])))
        destinations_by_legacy[record["path"]] = destinations
        legacy_records.append(
            {
                "destinations": list(destinations),
                "disposition": record["disposition"],
                "kind": record["kind"],
                "owner": record.get("milestone_owner"),
                "path": record["path"],
                "public_entry_points": public_entry_points,
                "rationale": _legacy_rationale(record, destinations),
                "responsibility": record["responsibility"],
                "status": record["status"],
            }
        )

    v5_artifacts = []
    for artifact in release_files():
        predecessors = sorted(
            legacy
            for legacy, destinations in destinations_by_legacy.items()
            if any(_covers(destination, artifact) for destination in destinations)
        )
        relative = artifact.removeprefix("src/claasp/")
        category = relative.split("/", 1)[0] if "/" in relative else "root"
        entry = {
            "classification": "legacy-lineage" if predecessors else "new-v5",
            "legacy_predecessors": predecessors,
            "path": artifact,
        }
        if not predecessors:
            entry["rationale"] = NEW_V5_RATIONALES[category]
        v5_artifacts.append(entry)

    dispositions = Counter(record["disposition"] for record in legacy_records)
    reverse = Counter(record["classification"] for record in v5_artifacts)
    return {
        "legacy_records": legacy_records,
        "milestone": "M11a",
        "schema_version": 1,
        "summary": {
            "legacy_by_disposition": dict(sorted(dispositions.items())),
            "legacy_records": len(legacy_records),
            "v5_artifacts": len(v5_artifacts),
            "v5_by_classification": dict(sorted(reverse.items())),
        },
        "v5_artifacts": v5_artifacts,
    }


def _markdown_cell(value: object) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text or "—"


def _legacy_relationship(record: dict[str, Any], destination_sources: dict[str, set[str]]) -> str:
    destinations = record["destinations"]
    if record["disposition"] == "remove":
        return "removed"
    if record["disposition"] == "inapplicable":
        return "inapplicable"
    if not destinations:
        return "evidence-only"
    if len(destinations) > 1:
        return "split"
    if any(len(destination_sources[destination]) > 1 for destination in destinations):
        return "consolidated"
    return "direct"


def render_summary(matrix: dict[str, Any]) -> str:
    """Render the exhaustive human comparison paired with the machine matrix."""
    summary = matrix["summary"]
    artifacts = matrix["v5_artifacts"]
    legacy = matrix["legacy_records"]
    grouped: dict[str, list[str]] = defaultdict(list)
    for record in artifacts:
        if record["classification"] == "new-v5":
            relative = record["path"].removeprefix("src/claasp/")
            category = relative.split("/", 1)[0] if "/" in relative else "root"
            grouped[category].append(record["path"])

    destination_sources: dict[str, set[str]] = defaultdict(set)
    for record in legacy:
        for destination in record["destinations"]:
            destination_sources[destination].add(record["path"])
    relationship_counts = Counter(
        _legacy_relationship(record, destination_sources) for record in legacy
    )

    lines = [
        "# Final bidirectional migration audit",
        "",
        "This generated M11a comparison is review material; the JSON matrix and closure tool are authoritative.",
        "",
        f"- Legacy records: {summary['legacy_records']}",
        f"- Shipped v5 artifacts: {summary['v5_artifacts']}",
        "- Legacy dispositions: "
        + ", ".join(f"{name}={count}" for name, count in summary["legacy_by_disposition"].items()),
        "- Reverse classifications: "
        + ", ".join(f"{name}={count}" for name, count in summary["v5_by_classification"].items()),
        "- Mapping relationships: "
        + ", ".join(f"{name}={count}" for name, count in sorted(relationship_counts.items())),
        "",
        "Every legacy source module, test module, and package marker appears below with its final disposition and reason. Every shipped v5 module or data artifact appears in the reverse table with its predecessor(s) or a new-v5 rationale.",
        "",
        "Relationship means: **direct** for one reviewed destination, **split** for one legacy record mapped to multiple destinations, **consolidated** when multiple legacy records share a destination, **evidence-only** when a test or cross-cutting record is closed by its recorded reason without one shipped source path, **removed** for deliberately dropped behavior, and **inapplicable** for non-behavioral or out-of-scope records.",
        "",
        "## Complete legacy-to-v5 mapping",
        "",
        "| Legacy path | Kind | Public entry points | Disposition | Relationship | v5 destination(s) | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for record in legacy:
        destinations = "<br>".join(f"`{path}`" for path in record["destinations"]) or "—"
        public = ", ".join(f"`{name}`" for name in record["public_entry_points"]) or "—"
        relationship = _legacy_relationship(record, destination_sources)
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{record['path']}`",
                    _markdown_cell(record["kind"]),
                    public,
                    _markdown_cell(record["disposition"]),
                    relationship,
                    destinations,
                    _markdown_cell(record["rationale"]),
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Complete v5-to-legacy mapping",
            "",
            "| Shipped v5 artifact | Classification | Relationship | Legacy predecessor(s) or new-v5 reason |",
            "|---|---|---|---|",
        ]
    )
    for record in artifacts:
        predecessors = record["legacy_predecessors"]
        if predecessors:
            evidence = "<br>".join(f"`{path}`" for path in predecessors)
            relationship = "consolidated" if len(predecessors) > 1 else "direct"
        else:
            evidence = _markdown_cell(record["rationale"])
            relationship = "new"
        lines.append(
            f"| `{record['path']}` | {record['classification']} | {relationship} | {evidence} |"
        )

    lines.extend(["", "## New-v5 artifact rationale groups", ""])
    for category in sorted(grouped):
        lines.extend(
            [
                f"### {category}",
                "",
                NEW_V5_RATIONALES[category],
                "",
                *[f"- `{path}`" for path in grouped[category]],
                "",
            ]
        )
    return "\n".join(lines)


def validate_matrix(matrix: dict[str, Any]) -> list[str]:
    """Return deterministic closure violations for a candidate matrix."""
    errors: list[str] = []
    if matrix.get("schema_version") != 1 or matrix.get("milestone") != "M11a":
        errors.append("matrix identity or schema is invalid")
    legacy = matrix.get("legacy_records")
    artifacts = matrix.get("v5_artifacts")
    if not isinstance(legacy, list) or not isinstance(artifacts, list):
        return errors + ["matrix record lists are missing"]
    legacy_paths = [record.get("path") for record in legacy if isinstance(record, dict)]
    artifact_paths = [record.get("path") for record in artifacts if isinstance(record, dict)]
    expected_inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))["records"]
    if legacy_paths != [record["path"] for record in expected_inventory]:
        errors.append("legacy record coverage or order is stale")
    if artifact_paths != release_files():
        errors.append("shipped v5 artifact coverage or order is stale")
    if len(legacy_paths) != len(set(legacy_paths)) or len(artifact_paths) != len(
        set(artifact_paths)
    ):
        errors.append("matrix contains duplicate identities")

    allowed = {"migrate", "supersede", "remove", "inapplicable"}
    for record in legacy:
        if not isinstance(record, dict):
            errors.append("legacy matrix entry is not an object")
            continue
        if record.get("disposition") not in allowed or "planned" in str(record.get("status")):
            errors.append(f"legacy disposition is not final: {record.get('path')}")
        if not record.get("rationale"):
            errors.append(f"legacy reason is missing: {record.get('path')}")
        public = record.get("public_entry_points")
        if not isinstance(public, list) or len(public) != len(set(public)):
            errors.append(f"legacy public entry points are malformed: {record.get('path')}")
        for destination in record.get("destinations", ()):
            if not (ROOT / destination).exists():
                errors.append(
                    f"legacy destination is missing: {record.get('path')} -> {destination}"
                )
    known_legacy = set(legacy_paths)
    for record in artifacts:
        if not isinstance(record, dict):
            errors.append("v5 matrix entry is not an object")
            continue
        predecessors = record.get("legacy_predecessors")
        if not isinstance(predecessors, list) or predecessors != sorted(set(predecessors)):
            errors.append(f"v5 predecessors are malformed: {record.get('path')}")
            continue
        if unknown := set(predecessors) - known_legacy:
            errors.append(f"v5 predecessors are stale: {record.get('path')} -> {sorted(unknown)}")
        classification = record.get("classification")
        if classification == "legacy-lineage" and not predecessors:
            errors.append(f"legacy-lineage artifact lacks a predecessor: {record.get('path')}")
        elif classification == "new-v5":
            if predecessors or not record.get("rationale"):
                errors.append(f"new-v5 rationale is missing or contradictory: {record.get('path')}")
        elif classification != "legacy-lineage":
            errors.append(f"invalid v5 classification: {record.get('path')}")
    if matrix.get("summary") != build_matrix()["summary"]:
        errors.append("matrix summary is stale")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if args.check == args.write:
        parser.error("choose exactly one of --check or --write")
    expected = build_matrix()
    serialized = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    summary = render_summary(expected)
    if args.write:
        MATRIX.write_text(serialized, encoding="utf-8")
        SUMMARY.write_text(summary, encoding="utf-8")
        print(f"wrote {MATRIX.relative_to(ROOT)} and {SUMMARY.relative_to(ROOT)}")
        return 0
    if not MATRIX.is_file() or MATRIX.read_text(encoding="utf-8") != serialized:
        print("bidirectional migration matrix is stale; run with --write")
        return 1
    committed = json.loads(MATRIX.read_text(encoding="utf-8"))
    errors = validate_matrix(committed)
    if SUMMARY.read_text(encoding="utf-8") != render_summary(committed):
        errors.append("human migration summary is stale")
    if errors:
        print("\n".join(errors))
        return 1
    counts = committed["summary"]
    print(
        "M11a bidirectional audit passes: "
        f"{counts['legacy_records']} legacy records, {counts['v5_artifacts']} shipped v5 artifacts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
