#!/usr/bin/env python3
"""Generate the committed v5 discovery catalogue from migration authorities."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
from pathlib import Path

from catalogue_classification import classify_bijectivity


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
    "Identity", "Permutation",
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
    ("component_bounded", "analysis_driver", "builtin", None,
     "claasp_next.drivers.analysis:BoundedBranchNumberDriver"),
    ("component_minizinc", "analysis_driver", "executable", "minizinc",
     "claasp_next.drivers.analysis:MiniZincBranchNumberDriver"),
    ("text_presentation", "renderer", "builtin", None,
     "claasp_next.presentation:render_report"),
    ("matplotlib_presentation", "renderer", "python_module", "matplotlib",
     "claasp_next.drivers.renderers.presentation:MatplotlibPresentationDriver"),
    ("ascii_diagram", "renderer", "builtin", None,
     "claasp_next.representations.diagrams:ASCIIArtSerializer"),
    ("tikz_diagram", "renderer", "builtin", None,
     "claasp_next.representations.diagrams:TikZSerializer"),
    ("python_source_compiler", "compiler", "builtin", None,
     "claasp_next.representations.source:compile_python_source"),
    ("python_generated_source", "execution_engine", "builtin", None,
     "claasp_next.drivers.source:run_python_source"),
    ("c_source_compiler", "compiler", "builtin", None,
     "claasp_next.representations.source:compile_c_source"),
    ("native_generated_c", "execution_engine", "executable", "cc",
     "claasp_next.drivers.native:compile_native"),
)

ALL_COMPONENTS = frozenset({
    "Add", "BinaryAffineMap", "BitVectorSBox", "BitwiseAnd", "BitwiseNot", "BitwiseOr",
    "Constant", "FeedbackRegister", "IDEAMultiply", "Identity", "LinearMap",
    "ModularAdd", "ModularMultiply", "ModularSubtract", "Multiply", "Permutation",
    "Power", "Rotate", "SBox", "Shift", "VariableRotate", "VariableShift", "Xor",
})
ALL_DOMAINS = frozenset({"BinaryExtensionField", "Bit", "PrimeField", "Word"})
BOOLEAN_CNF_COMPONENTS = frozenset({
    "Add", "BitVectorSBox", "BitwiseAnd", "Constant", "Identity",
    "ModularAdd", "Permutation", "Rotate", "Xor",
})
BOOLEAN_SYMBOLIC_COMPONENTS = frozenset({
    "BitwiseAnd", "BitwiseNot", "BitwiseOr", "Constant", "ModularAdd", "Rotate", "Xor",
})
PRIME_FIELD_POLYNOMIAL_COMPONENTS = frozenset({
    "Add", "Constant", "Identity", "LinearMap", "Multiply", "Permutation", "Power",
})
WORD_TRAIL_COMPONENTS = frozenset({
    "BitwiseAnd", "Constant", "Identity", "ModularAdd", "Rotate", "Xor",
})
C_SOURCE_COMPONENTS = frozenset({
    "BitVectorSBox", "BitwiseAnd", "BitwiseNot", "BitwiseOr", "Constant",
    "Identity", "ModularAdd", "ModularSubtract", "Permutation", "Rotate",
    "Shift", "VariableRotate", "VariableShift", "Xor",
})

# These declarations are reviewed compatibility edges, not filesystem-derived
# guesses.  A representation is advertised for a component only when its
# current lowering/evaluator has explicit semantics for that component.
REPRESENTATIONS = (
    ("boolean_cnf", "constraint", "claasp_next.representations.constraints.sat:BooleanCNFModel",
     BOOLEAN_CNF_COMPONENTS, {"Bit", "Word"}, {"minizinc", "minisat", "z3", "glpk"}, "generic_graph"),
    ("boolean_degree_bounds", "analysis", "claasp_next.representations.execution:BooleanDegreeEvaluator",
     BOOLEAN_SYMBOLIC_COMPONENTS, {"Bit", "Word"}, set(), "generic_graph"),
    ("boolean_monomial_milp", "constraint", "claasp_next.representations.constraints.milp:BooleanMonomialGraphMILPModel",
     {"BitwiseAnd", "Constant", "Rotate", "Xor"}, {"Bit", "Word"}, {"glpk"}, "generic_graph"),
    ("boolean_smt", "constraint", "claasp_next.representations.constraints.smt:BooleanSMTModel",
     BOOLEAN_CNF_COMPONENTS, {"Bit", "Word"}, {"z3"}, "generic_graph"),
    ("boolean_symbolic_anf", "analysis", "claasp_next.representations.execution:BooleanSymbolicEvaluator",
     BOOLEAN_SYMBOLIC_COMPONENTS, {"Bit", "Word"}, set(), "generic_graph"),
    ("concrete_execution", "execution", "claasp_next.graph:Primitive",
     ALL_COMPONENTS, ALL_DOMAINS, {"python_scalar", "python_batch", "python_transposed_batch"}, "generic_graph"),
    ("primitive_serialization", "serialization", "claasp_next.serialization:serialize_primitive",
     ALL_COMPONENTS, ALL_DOMAINS, set(), "generic_graph"),
    ("execution_artifact_serialization", "serialization", "claasp_next.serialization:serialize_artifact",
     set(), ALL_DOMAINS, set(), "result"),
    ("python_generated_source", "source", "claasp_next.representations.source:compile_python_source",
     ALL_COMPONENTS, ALL_DOMAINS, {"python_source_compiler", "python_generated_source"}, "generic_graph"),
    ("c_generated_source", "source", "claasp_next.representations.source:compile_c_source",
     C_SOURCE_COMPONENTS, {"Bit", "Word"}, {"c_source_compiler", "native_generated_c"}, "generic_graph"),
    ("msolve_input", "serialization", "claasp_next.representations.constraints.polynomial.exporters:MsolveExporter",
     PRIME_FIELD_POLYNOMIAL_COMPONENTS, {"PrimeField"}, {"msolve"}, "generic_graph"),
    ("prime_field_polynomial", "constraint", "claasp_next.representations.constraints.polynomial:PrimeFieldPolynomialModel",
     PRIME_FIELD_POLYNOMIAL_COMPONENTS, {"PrimeField"}, set(), "generic_graph"),
    ("primitive_diagram", "diagram", "claasp_next.representations.diagrams:DiagramCompiler",
     ALL_COMPONENTS, ALL_DOMAINS, {"ascii_diagram", "tikz_diagram", "latex"}, "generic_graph"),
    ("sbox_transition_table", "analysis", "claasp_next.semantics.cryptanalysis:SBoxTransitionSemantics",
     {"BitVectorSBox"}, {"Bit"}, set(), "component"),
    ("singular_program", "serialization", "claasp_next.representations.constraints.polynomial.exporters:SingularExporter",
     PRIME_FIELD_POLYNOMIAL_COMPONENTS, {"PrimeField"}, {"singular"}, "generic_graph"),
    ("word_differential_smt", "constraint", "claasp_next.representations.constraints.smt:WordDifferentialSMTModel",
     WORD_TRAIL_COMPONENTS, {"Word"}, {"z3"}, "generic_graph"),
    ("word_linear_smt", "constraint", "claasp_next.representations.constraints.smt:WordLinearSMTModel",
     WORD_TRAIL_COMPONENTS, {"Word"}, {"z3"}, "generic_graph"),
    ("component_properties", "analysis", "claasp_next.analysis:analyze_component_property",
     {"BinaryAffineMap", "BitVectorSBox", "BitwiseAnd", "BitwiseNot", "BitwiseOr",
      "FeedbackRegister", "LinearMap", "ModularAdd", "Permutation", "Rotate", "SBox",
      "Shift", "Xor"}, ALL_DOMAINS, {"component_bounded", "component_minizinc"}, "component"),
    ("report_presentation", "presentation", "claasp_next.presentation:ReportData",
     set(), set(), {"text_presentation", "matplotlib_presentation"}, "result"),
)

ANALYSES = (
    ("component_property", "Primitive.analyze().component_property", "component_property",
     "qualified", {"component_properties"}, {"component_bounded", "component_minizinc"}, set(), set(),
     "applicability and evidence strength are reported per semantic component and domain"),
    ("avalanche", "Primitive.analyze().avalanche", "statistical", "empirical",
     {"concrete_execution"}, {"python_scalar"}, set(), set(), None),
    ("enumerate_solutions", "Primitive.analyze().enumerate_solutions", "constraint", "exact",
     {"boolean_cnf"}, {"minizinc", "minisat", "z3", "glpk"}, set(), set(), None),
    ("enumerate_xor_differential_trails", "Primitive.analyze().enumerate_xor_differential_trails",
     "xor_differential", "exact_characteristic", {"word_differential_smt"}, {"z3"}, set(), set(), None),
    ("enumerate_xor_linear_trails", "Primitive.analyze().enumerate_xor_linear_trails",
     "xor_linear", "exact_characteristic", {"word_linear_smt"}, {"z3"}, set(), set(), None),
    ("find_lowest_weight_xor_differential_trail",
     "Primitive.analyze().find_lowest_weight_xor_differential_trail", "xor_differential", "exact",
     set(), set(), set(), {"Present", "Speck"}, "reviewed reduced-round slice only"),
    ("find_lowest_weight_xor_linear_trail", "Primitive.analyze().find_lowest_weight_xor_linear_trail",
     "xor_linear", "exact", set(), set(), set(), {"Present", "Speck"},
     "reviewed reduced-round slice only"),
    ("is_xor_differential_transition_possible",
     "Primitive.analyze().is_xor_differential_transition_possible", "component_transition", "exact",
     {"sbox_transition_table"}, set(), {"BitVectorSBox"}, set(), None),
    ("recover_input", "Primitive.analyze().recover_input", "constraint", "exact",
     {"boolean_cnf"}, {"minizinc", "minisat", "z3", "glpk"}, set(), set(), None),
    ("solve", "Primitive.analyze().solve", "constraint", "exact",
     {"boolean_cnf"}, {"minizinc", "minisat", "z3", "glpk"}, set(), set(), None),
    ("present", "claasp_next.presentation.present", "result_presentation", "qualified",
     {"report_presentation"}, {"text_presentation", "matplotlib_presentation"}, set(), set(),
     "consumes already-produced typed results and never executes an analysis"),
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
            fallback_obligation, fallback_basis = classify_bijectivity(name, category)
            classification = source["primitive"] if source is not None else {
                "official_name": name,
                "input_roles": [
                    descriptor.role for descriptor in primitive.input_descriptors.values()
                ],
                "bijectivity_obligation": fallback_obligation,
                "classification_basis": fallback_basis,
            }
            component_names = {type(component).__name__ for component in primitive.components}
            domain_names = {
                type(port.value_type.domain).__name__ for port in primitive.input_ports.values()
            } | {type(component.output_type.domain).__name__ for component in primitive.components}
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
                "domains": sorted(domain_names),
                "tags": _tags(category, component_names),
                "authenticity": (
                    "noncanonical_legacy_regression"
                    if name in LEGACY_REGRESSIONS else "canonical"
                ),
                "labels": sorted(labels),
                "legacy_source": source["path"] if source is not None else None,
                "classification_basis": (
                    classification.get("classification_basis")
                    or fallback_basis
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
    representations = [
        {"name": name, "kind": kind, "implementation": implementation,
         "components": sorted(components), "domains": sorted(domains),
         "drivers": sorted(drivers), "scope": scope}
        for name, kind, implementation, components, domains, drivers, scope in REPRESENTATIONS
    ]
    representation_names_by_driver = {
        driver: sorted(item[0] for item in REPRESENTATIONS if driver in item[5])
        for driver, *_ in DRIVERS
    }
    drivers = [
        {"name": name, "kind": kind, "availability": availability,
         "target": target, "implementation": implementation,
         "representations": representation_names_by_driver[name]}
        for name, kind, availability, target, implementation in DRIVERS
    ]
    analyses = [
        {"name": name, "entry_point": entry_point, "kind": kind, "evidence": evidence,
         "representations": sorted(representations_), "drivers": sorted(drivers_),
         "required_components": sorted(required_components), "primitives": sorted(primitives_),
         "restriction": restriction}
        for (name, entry_point, kind, evidence, representations_, drivers_, required_components,
             primitives_, restriction) in ANALYSES
    ]
    return {
        "schema_version": 2,
        "milestone": "M10.15g",
        "sources": {
            "classification": "migration/legacy_inventory.json",
            "components": "migration/single_component_catalogue.json",
            "realizations": "migration/realization_catalogue.json",
        },
        "primitives": primitives,
        "components": components,
        "representations": representations,
        "analyses": analyses,
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
            f"{len(payload['components'])} components, "
            f"{len(payload['representations'])} representations, "
            f"{len(payload['analyses'])} analyses, {len(payload['drivers'])} drivers"
        )
        return
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(serialized, encoding="utf-8")
    print(
        f"wrote {DESTINATION.relative_to(ROOT)} with "
        f"{len(payload['primitives'])} primitives, {len(payload['components'])} components, "
        f"{len(payload['representations'])} representations, {len(payload['analyses'])} analyses, "
        f"and {len(payload['drivers'])} drivers"
    )


if __name__ == "__main__":
    main()
