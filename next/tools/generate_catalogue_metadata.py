#!/usr/bin/env python3
"""Generate the committed v5 discovery catalogue from migration authorities."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
INVENTORY = ROOT / "migration/legacy_inventory.json"
REALIZATIONS = ROOT / "migration/realization_catalogue.json"
SINGLE_COMPONENTS = ROOT / "migration/single_component_catalogue.json"
DESTINATION = ROOT / "src/claasp_next/catalogue/data/catalogue.json"

LEGACY_REGRESSIONS = frozenset({"GimliSbox", "SimeckSbox", "SimonSbox"})
EQUIVALENT_EXPORTS = frozenset({
    "AradiSBox", "AradiSBoxCompactLinearMap", "AsconSboxSigma",
    "AsconSboxSigmaNoMatrix", "GastonSbox", "GastonSboxTheta", "GiftSbox",
    "KatanFSR", "KeccakSbox", "KtantanFSR", "QARMAv2MixColumn",
    "SpongentPiPrecomputation", "TinyJambuFSRWordBased", "TinyJambuWordBased",
    "UblockSingleLinearLayer", "XoodooSbox",
})
EXACT_ALIASES = frozenset({"KeccakInvertible", "SpongentPiFSR", "XoodooInvertible"})
STRUCTURAL_COMPONENTS = frozenset({
    "Concatenate", "Identity", "PackBits", "Permutation", "UnpackBits",
})
DRIVERS = (
    ("python_scalar", "execution_engine", "builtin", None,
     "claasp_next.representations.execution:ScalarExecutionDriver"),
    ("python_batch", "execution_engine", "builtin", None,
     "claasp_next.representations.execution:BatchExecutionDriver"),
    ("python_transposed_batch", "execution_engine", "builtin", None,
     "claasp_next.representations.execution:TransposedBatchExecutionDriver"),
    ("minizinc", "solver", "executable", "minizinc",
     "claasp_next.drivers.solvers.minizinc:MiniZincSolver"),
    ("minizinc_chuffed", "solver", "minizinc_solver", "minizinc:chuffed",
     "claasp_next.drivers.solvers.minizinc:MiniZincSolver"),
    ("minisat", "solver", "executable", "minisat",
     "claasp_next.drivers.solvers.minisat:MinisatSolver"),
    ("z3", "solver", "executable", "z3",
     "claasp_next.drivers.solvers.z3:Z3Solver"),
    ("glpk", "solver", "executable", "glpsol",
     "claasp_next.drivers.solvers.glpk:GLPKSolver"),
    ("singular", "solver", "executable", "Singular",
     "claasp_next.drivers.algebra.singular:SingularDriver"),
    ("msolve", "solver", "executable", "msolve",
     "claasp_next.drivers.algebra.msolve:MsolveDriver"),
    ("dieharder", "external_tool", "executable", "dieharder",
     "claasp_next.drivers.statistical.dieharder:DieharderDriver"),
    ("nist_sts", "external_tool", "executable", "niststs",
     "claasp_next.drivers.statistical.nist:NistStsDriver"),
    ("latex", "renderer", "executable", "pdflatex",
     "claasp_next.drivers.renderers.latex:LaTeXDriver"),
    ("sklearn_mlp", "external_tool", "python_module", "sklearn",
     "claasp_next.drivers.neural.sklearn_driver:SklearnMLPDriver"),
)


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
    if configurations:
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


def build_catalogue() -> dict:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    realization_audit = json.loads(REALIZATIONS.read_text(encoding="utf-8"))
    single_components = json.loads(SINGLE_COMPONENTS.read_text(encoding="utf-8"))
    source_records = {
        item["primitive"]["proposed_class"]: item
        for item in inventory["records"]
        if item.get("kind") == "source" and "primitive" in item
        and item["primitive"]["primitive_category"] != "outside_scope"
    }
    test_evidence = {}
    for item in inventory["records"]:
        owner = item.get("milestone_owner")
        if item.get("kind") != "test" or not owner:
            continue
        test_evidence.setdefault(owner, set()).update(
            path.strip() for path in item.get("v5_destination", "").split(";") if path.strip()
        )

    from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS

    canonical_realization_classes = {
        item["canonical"].split(":", 1)[1] for item in realization_audit["families"]
    }
    primitives = []
    for category, exports in sorted(CATEGORY_EXPORTS.items()):
        for name, module_name in sorted(exports.items()):
            module = importlib.import_module(module_name)
            primitive_class = getattr(module, name)
            primitive = primitive_class()
            source = source_records.get(name)
            classification = source["primitive"] if source is not None else {
                "official_name": name,
                "input_roles": [
                    descriptor.role for descriptor in primitive.input_descriptors.values()
                ],
                "bijectivity_obligation": primitive.kind.value == "permutation",
            }
            component_names = {type(component).__name__ for component in primitive.components}
            labels = []
            if name in EQUIVALENT_EXPORTS:
                labels.append("equivalent_realization")
            if name in EXACT_ALIASES:
                labels.append("exact_alias")
            if name in LEGACY_REGRESSIONS:
                labels.append("noncanonical_legacy_regression")
            if name in canonical_realization_classes:
                labels.append("realization_family")
            evidence = (
                sorted(test_evidence.get(source.get("milestone_owner"), ()))
                if source is not None else ["next/tests/unit/test_single_component_primitives.py"]
            )
            primitives.append({
                "name": name,
                "official_name": classification["official_name"],
                "module": module_name,
                "category": category,
                "family": primitive.family_name,
                "kind": primitive.kind.value,
                "input_roles": list(classification["input_roles"]),
                "inputs": [
                    {"name": input_name, "role": descriptor.role,
                     "visibility": descriptor.visibility.value}
                    for input_name, descriptor in primitive.input_descriptors.items()
                ],
                "bijectivity_obligation": classification["bijectivity_obligation"],
                "components": sorted(component_names),
                "tags": _tags(category, component_names),
                "authenticity": (
                    "noncanonical_legacy_regression"
                    if name in LEGACY_REGRESSIONS else "canonical"
                ),
                "labels": sorted(labels),
                "legacy_source": source["path"] if source is not None else None,
                "classification_basis": (
                    classification.get("classification_basis")
                    or "new v5 base-component primitive classified by its typed boundary"
                ),
                "fixed_evidence": evidence,
                "parameter_sets": _parameter_sets(primitive_class, module),
                "realizations": [
                    {"name": descriptor.name,
                     "capabilities": sorted(descriptor.capabilities),
                     "structure": sorted(descriptor.structure),
                     "maturity": descriptor.maturity.value,
                     "provenance": list(descriptor.provenance),
                     "priority": descriptor.priority}
                    for descriptor in primitive_class.available_realizations()
                ],
            })

    components = [
        {"name": name, "module": module, "primitive_wrapper": name}
        for name, module in sorted(single_components.items())
    ]
    drivers = [
        {"name": name, "kind": kind, "availability": availability,
         "target": target, "implementation": implementation}
        for name, kind, availability, target, implementation in DRIVERS
    ]
    return {
        "schema_version": 1,
        "milestone": "M10.9f1",
        "sources": {
            "classification": "migration/legacy_inventory.json",
            "components": "migration/single_component_catalogue.json",
            "realizations": "migration/realization_catalogue.json",
        },
        "primitives": primitives,
        "components": components,
        "drivers": drivers,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed metadata is stale")
    arguments = parser.parse_args()
    payload = build_catalogue()
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.check:
        if not DESTINATION.is_file() or DESTINATION.read_text(encoding="utf-8") != serialized:
            raise SystemExit("committed catalogue metadata is stale; regenerate it")
        print(
            f"catalogue metadata: {len(payload['primitives'])} primitives, "
            f"{len(payload['components'])} components, {len(payload['drivers'])} drivers"
        )
        return
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(serialized, encoding="utf-8")
    print(
        f"wrote {DESTINATION.relative_to(ROOT)} with "
        f"{len(payload['primitives'])} primitives, {len(payload['components'])} components, "
        f"and {len(payload['drivers'])} drivers"
    )


if __name__ == "__main__":
    main()
