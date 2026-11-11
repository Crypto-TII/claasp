#!/usr/bin/env python3
"""Generate the committed v5 discovery catalogue from implementation-owned declarations."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
from pathlib import Path
from typing import Any

from catalogue_classification import classify_bijectivity
from catalogue_discovery import (
    analysis_records,
    component_records,
    discover,
    driver_records,
    primitive_exports,
    representation_records,
    validate_payload,
)

ROOT = Path(__file__).parents[1]
INVENTORY = ROOT / "tools/data/legacy_inventory.json"
INVENTORY_DELTA = ROOT / "tools/data/legacy_inventory_delta.json"
REALIZATIONS = ROOT / "tools/data/realization_catalogue.json"
DESTINATION = ROOT / "src/claasp/catalogue/data/catalogue.json"
STRUCTURAL_COMPONENTS = frozenset({"Identity", "Permutation"})


def _json_value(value):
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return None
    return value


def _parameter_sets(primitive_class, module) -> list[dict]:
    configurations = getattr(module, "PARAMETERS_CONFIGURATION_LIST", None)
    if configurations is None:
        configurations = getattr(primitive_class, "PARAMETERS_CONFIGURATION_LIST", None)
    if configurations and all(
        set(configuration) <= set(inspect.signature(primitive_class).parameters)
        for configuration in configurations
    ):
        return [
            {"name": f"standard-{index + 1}", "values": dict(configuration)}
            for index, configuration in enumerate(configurations)
        ]
    defaults = {}
    for name, parameter in inspect.signature(primitive_class).parameters.items():
        if parameter.default is inspect.Parameter.empty:
            continue
        value = _json_value(parameter.default)
        if value is not None or parameter.default is None:
            defaults[name] = value
    return [{"name": "default", "values": defaults}]


def _tags(category: str, component_names: set[str]) -> list[str]:
    tags = {category}
    semantic = component_names - STRUCTURAL_COMPONENTS
    if component_names & {"BitVectorSBox", "SBox"}:
        tags.add("sbox_based")
    if "FeedbackRegister" in component_names:
        tags.add("fsr_based")
    if category == "tweakable_block_ciphers":
        tags.add("tweakable_block_cipher")
    if semantic == {"ModularAdd", "Rotate", "Xor"}:
        tags.update(("arx", "purearx"))
    elif semantic == {"Constant", "ModularAdd", "Rotate", "Xor"}:
        tags.add("arx")
    if semantic == {"BitwiseAnd", "Rotate", "Xor"}:
        tags.update(("andrx", "pureandrx"))
    elif semantic == {"BitwiseAnd", "Constant", "Rotate", "Xor"}:
        tags.add("andrx")
    return sorted(tags)


def build_catalogue(entries=None) -> dict:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    inventory["records"] += json.loads(INVENTORY_DELTA.read_text(encoding="utf-8"))["records"]
    realization_audit = json.loads(REALIZATIONS.read_text(encoding="utf-8"))
    entries = discover() if entries is None else entries
    primitive_entries = {
        row.name: row for row in entries if row.declaration.category == "primitive"
    }
    source_records = {
        item["primitive"]["proposed_class"]: item
        for item in inventory["records"]
        if item.get("kind") == "source"
        and "primitive" in item
        and item["primitive"]["primitive_category"] != "outside_scope"
    }
    test_evidence: dict[str, set[str]] = {}
    for item in inventory["records"]:
        owner = item.get("milestone_owner")
        if item.get("kind") != "test" or not owner:
            continue
        test_evidence.setdefault(owner, set()).update(
            path.strip() for path in item.get("v5_destination", "").split(";") if path.strip()
        )

    categories: dict[str, dict[str, str]] = {}
    for category, name, owner in primitive_exports(entries):
        categories.setdefault(category, {})[name] = owner

    canonical_realization_classes = {
        item["canonical"].split(":", 1)[1] for item in realization_audit["families"]
    }
    primitives = []
    for category, exports in sorted(categories.items()):
        for name, module_name in sorted(exports.items()):
            module = importlib.import_module(module_name)
            primitive_class = getattr(module, name)
            declaration = primitive_entries[name].declaration
            example = declaration.metadata.get("example")
            primitive = primitive_class(**({} if example is None else example))
            source = source_records.get(name)
            fallback_obligation, fallback_basis = classify_bijectivity(name, category)
            classification: dict[str, Any] = (
                source["primitive"]
                if source is not None
                else {
                    "official_name": name,
                    "input_roles": [
                        descriptor.role for descriptor in primitive.graph.input_descriptors.values()
                    ],
                    "bijectivity_obligation": fallback_obligation,
                    "classification_basis": fallback_basis,
                }
            )
            component_names = {type(component).__name__ for component in primitive.graph.components}
            domain_names = {
                type(unit_array.array_type.unit_type).__name__
                for unit_array in primitive.graph.input_arrays.values()
            } | {
                type(component.output_type.unit_type).__name__
                for component in primitive.graph.components
            }
            labels = list(declaration.metadata.get("labels", ()))
            if name in canonical_realization_classes:
                labels.append("realization_family")
            evidence = (
                sorted(test_evidence.get(source.get("milestone_owner"), ()))
                if source is not None
                else list(
                    declaration.metadata.get(
                        "evidence",
                        ("tests/unit/primitives/single_component_primitives/test_package.py",),
                    )
                )
            )
            primitives.append(
                {
                    "name": name,
                    "official_name": classification["official_name"],
                    "module": module_name,
                    "category": category,
                    "family": primitive.family_name,
                    "kind": primitive.kind.value,
                    "input_roles": list(classification["input_roles"]),
                    "inputs": [
                        {
                            "name": input_name,
                            "role": descriptor.role,
                            "visibility": descriptor.visibility.value,
                        }
                        for input_name, descriptor in primitive.graph.input_descriptors.items()
                    ],
                    "bijectivity_obligation": classification["bijectivity_obligation"],
                    "components": sorted(component_names),
                    "domains": sorted(domain_names),
                    "tags": _tags(category, component_names),
                    "authenticity": (
                        "noncanonical_legacy_regression"
                        if "noncanonical_legacy_regression" in labels
                        else "canonical"
                    ),
                    "labels": sorted(labels),
                    "legacy_source": source["path"] if source is not None else None,
                    "classification_basis": (
                        classification.get("classification_basis") or fallback_basis
                    ),
                    "fixed_evidence": evidence,
                    "parameter_sets": (
                        [{"name": "teaching-example", "values": dict(example)}]
                        if example is not None
                        else _parameter_sets(primitive_class, module)
                    ),
                    "realizations": [
                        {
                            "name": descriptor.name,
                            "capabilities": sorted(descriptor.capabilities),
                            "structure": sorted(descriptor.structure),
                            "maturity": descriptor.maturity.value,
                            "provenance": list(descriptor.provenance),
                            "priority": descriptor.priority,
                        }
                        for descriptor in primitive_class.available_realizations()
                    ],
                }
            )

    components = component_records(entries)
    representations = representation_records(entries)
    drivers = driver_records(entries)
    for driver in drivers:
        driver["representations"] = sorted(
            row["name"] for row in representations if driver["name"] in row["drivers"]
        )
    analyses = analysis_records(entries)
    payload = {
        "schema_version": 2,
        "milestone": "M10.15g",
        "sources": {
            "classification": "tools/data/legacy_inventory.json",
            "membership": "implementation-owned __catalogue__ declarations",
            "components": "claasp.components public Component types",
            "realizations": "tools/data/realization_catalogue.json",
        },
        "primitives": primitives,
        "components": components,
        "representations": representations,
        "analyses": analyses,
        "drivers": drivers,
    }
    validate_payload(payload, entries)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed metadata is stale")
    arguments = parser.parse_args()
    from generate_primitive_exports import DESTINATION as EXPORTS_DESTINATION
    from generate_primitive_exports import render_exports

    entries = discover()
    payload = build_catalogue(entries)
    export_source, _ = render_exports(entries)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.check:
        if (
            not DESTINATION.is_file()
            or DESTINATION.read_text(encoding="utf-8") != serialized
            or not EXPORTS_DESTINATION.is_file()
            or EXPORTS_DESTINATION.read_text(encoding="utf-8") != export_source
        ):
            raise SystemExit(
                "committed catalogue metadata or exports are stale; run tools/generate_catalogue_metadata.py"
            )
        print(
            f"catalogue metadata: {len(payload['primitives'])} primitives, "
            f"{len(payload['components'])} components, "
            f"{len(payload['representations'])} representations, "
            f"{len(payload['analyses'])} analyses, {len(payload['drivers'])} drivers"
        )
        return
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(serialized, encoding="utf-8")
    EXPORTS_DESTINATION.write_text(export_source, encoding="utf-8")
    print(
        f"wrote {DESTINATION.relative_to(ROOT)} with "
        f"{len(payload['primitives'])} primitives, {len(payload['components'])} components, "
        f"{len(payload['representations'])} representations, {len(payload['analyses'])} analyses, "
        f"and {len(payload['drivers'])} drivers"
    )


if __name__ == "__main__":
    main()
