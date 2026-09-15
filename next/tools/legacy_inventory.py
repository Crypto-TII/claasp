#!/usr/bin/env python3
"""Build and verify the exhaustive CLAASP 4 Python migration inventory.

The output is deterministic and intentionally uses only the Python standard
library. Run from ``next/`` with ``python tools/legacy_inventory.py --check``.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any
import warnings


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "next" / "migration" / "legacy_inventory.json"
LEGACY_ROOTS = (ROOT / "claasp", ROOT / "tests")
SCHEMA_VERSION = 1

CATEGORY_BY_DIRECTORY = {
    "block_ciphers": "block_ciphers",
    "permutations": "permutations",
    "hash_functions": "functions",
    "mac": "block_functions",
    "stream_ciphers": "block_functions",
    "single_component_ciphers": "single_component_primitives",
    "toys": "toy_primitives",
}

MIGRATION_OVERRIDES = {
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed analysis constraints compile graph execution and projections; MiniZinc independently reproduces the full Speck-22 fixed output A86842F2.",
        "rationale": "The mutable legacy component-method factory, generated declarations and output directives are replaced by shared Boolean graph lowering and explicit projections. Unsupported components fail rather than printing and retaining stale constraints; per-component catalogue coverage is separately inventoried.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete Speck-22 execution is compiled and checked through the shared Boolean-to-CP representation.",
        "rationale": "The legacy optimized builder accepts only ROTATE, SHIFT and XOR and silently omits MODADD; its smoke test establishes no nonlinear correctness. v5 uses complete execution lowering with explicit unsupported-component errors, not an incomplete model labelled optimized.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/sat/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed fixed/equal/unequal/nonzero constraints and graph projections retain execution witnesses, including full Speck-22 output A86842F2 and Simon AND recovery.",
        "rationale": "Per-component method-name dictionaries, compact-graph mutation, solver registries and result-string parsing are replaced by immutable typed graph lowering and optional drivers. Shared exact/truncated phase composition is explicit, not hidden in a method-name factory.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/boolean.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every Boolean execution clause is translated exactly to a binary inequality; full Speck-22 scalar and GLPK witnesses reproduce A86842F2.",
        "rationale": "The legacy builder omits nonlinear operations and even documents that execution cannot be represented with inequalities. Binary clause inequalities do represent them exactly; the incomplete Sage model and its incidental 9296-constraint count are not retained.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "MiniZinc reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.", "rationale": None,
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_z3_integration.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Boolean CLI solving reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.", "rationale": None,
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete full-round execution is solved and independently validated rather than merely constructed.",
        "rationale": "The assertion-free legacy construction smoke test accepts a builder that skips modular addition; a checked complete execution witness supersedes it.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_cipher_model_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_graph_milp.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact binary-linear clauses match complete truth tables and full Speck-22 graph witnesses, including modular additions omitted by the legacy builder.",
        "rationale": "Legacy Sage variable names, first/last wiring inequalities and the count 9296 describe an incomplete encoding, not a fixed scientific result.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/model.py",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed model declarations retain explicit identities; no variable groups are inferred by parsing declaration strings.",
        "rationale": "The only helpers filter declaration strings and infer groups from legacy _y names. Typed graph ports and immutable MiniZinc model parts remove this formatting-dependent responsibility.",
    },
    "claasp/cipher_modules/models/sat/utils/constants.py": {
        "v5_destination": "next/src/claasp_next/graph",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Input/output port identities and logical selections are typed independently of solver variable suffixes.",
        "rationale": "The file contains only _i and _o formatting constants, which are not v5 public model contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/milp_name_mappings.py": {
        "v5_destination": "next/src/claasp_next/semantics; next/src/claasp_next/representations/constraints/milp",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed semantic descriptors, objectives and result types distinguish mathematical problems from MILP representations.",
        "rationale": "Model dictionary tags, progress messages, decimal-weight precision and variable suffixes are removed; exact component probabilities and explicit objective descriptors own the scientific meaning.",
    },
    "claasp/cipher_modules/models/cp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minizinc.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Optional MiniZinc driver accepts an explicit solver id and executable without requiring a Python MiniZinc or Sage package.",
        "rationale": "Hard-coded command dictionaries, internal/external API duplicates, and assumed installed solver brands are replaced by explicit driver configuration and executable discovery. Proprietary MiniZinc solver ids can be selected optionally, never required by baseline CI.",
    },
    "claasp/cipher_modules/models/milp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/glpk.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "GLPK command driver provides a Sage-independent open MILP baseline; the portable representation and driver protocol do not depend on a proprietary optimizer.",
        "rationale": "The Sage backend registry, cwd captured at import time and solver-brand output regex dictionaries are not migrated APIs. Third-party optimizers can implement the explicit driver protocol without entering the core dependency set; this does not claim a v5 adapter exists for every legacy solver brand.",
    },
    "claasp/cipher_modules/models/sat/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minisat.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "MiniSat and CLI Z3 provide optional open Boolean solving with named assignments and independently verified witnesses.",
        "rationale": "Sage internal solver lists and command-format dictionaries are replaced by explicit driver objects. No installation is inferred from a registry entry. Legacy brand aliases and exact timing/memory log labels are not compatibility contracts; mathematical fixture ownership stays with separate inventoried model tests.",
    },
    "tests/unit/cipher_modules/models/sat/utils/sat_model_utils_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_cnf.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete OR truth-table support and multi-operand XOR intermediate/output witnesses are independently checked.",
        "rationale": "Specific literal-string ordering and intermediate names are replaced by deterministic numeric clauses, typed graph provenance and complete Boolean truth-table tests.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_minizinc_integration.py; next/tests/unit/test_bitwise_transition_semantics.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy Speck-2 exact weight-one count 6 and bounded count 7; toy Speck-4 weight-one UNSAT; identity lookup zero-weight feasibility and positive-weight UNSAT; Speck-5 optimum/fixed weight 9; exact AND DDT are independently preserved.",
        "rationale": "CLI solver drivers and typed independently checked characteristics replace Python MiniZinc API versus external-command duplicates, dictionary model/status tags and arbitrary intermediate component-value formatting. Identity lookup behavior is represented directly by typed Identity; fixed round-key differences are explicit.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_bitwise_transition_semantics.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete toy single-key enumeration retains 12 exact-weight-one and 13 bounded characteristics. Standard Speck-4 optimum and feasible weight 3 and the complete AND LAT are independently checked.",
        "rationale": "Explicit masks, typed results and terminal UNSAT replace legacy fixed-bit string formatters, scaled probability-array declarations, solve-with-API statistics dictionaries, and a hard-coded MiniZinc search annotation. No arbitrary witness or FancyBlockCipher declaration count is a public v5 contract.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py; next/tests/integration/test_minizinc_integration.py; next/tests/integration/test_speck_trail_enumeration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every fixed AES branch-table row, Midori active-count {3,4}, Speck-3 differential boundaries at weight 6, linear boundaries at weight 5, and boundary comparison SAT/UNSAT are independently preserved.",
        "rationale": "Typed immutable model parts, explicit phase composition and executable drivers replace mutable method-name dictionaries, legacy solver registries, declaration names and time-stat fallbacks. Unknown components fail explicitly rather than silently yielding a nonempty partial model. Intermediate output is not proof-complete evidence. Branch-bound rows remain an abstraction, not concrete MixColumns witnesses.",
    },
    "claasp/cipher_modules/models/algebraic/algebraic_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Typed polynomial lowering and exact Boolean symbolic evaluation retain equation "
            "provenance and independently validate graph evaluations."
        ),
        "rationale": (
            "v5 separates typed graph lowering, polynomial representations, and algebra drivers; "
            "legacy variable strings and a timeout-as-security boolean are not compatibility APIs."
        ),
    },
    "claasp/cipher_modules/models/algebraic/boolean_polynomial_ring.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "The dependency-free BooleanPolynomial type enforces square-free GF(2) arithmetic "
            "without a Sage ring type check."
        ),
        "rationale": "The legacy entry point only identifies Sage's BooleanPolynomialRing type.",
    },
    "claasp/cipher_modules/models/algebraic/constraints.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Dependency-free Boolean polynomial constraints preserve equality and exact modular "
            "addition/subtraction semantics, with explicit bit ordering."
        ),
        "rationale": (
            "The Sage polynomial-ring helpers are replaced by the square-free v5 Boolean "
            "polynomial representation."
        ),
    },
    "tests/unit/cipher_modules/models/algebraic/constraints_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_polynomial_constraints.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": (
            "Exhaustive dependency-free tests preserve vector equality and explicit/eliminated "
            "ripple addition and subtraction over complete small domains."
        ),
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/algebraic/algebraic_model_test.py": {
        "v5_destination": (
            "next/tests/unit/test_boolean_symbolic_evaluation.py; "
            "next/tests/unit/test_polynomial.py"
        ),
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Exact Boolean and prime-field graph evaluations satisfy their polynomial semantics; "
            "equation provenance and structural statistics are tested without Sage."
        ),
        "rationale": (
            "FancyBlockCipher-specific variable names and equation counts describe the removed "
            "legacy representation, while its timeout-based security claim is not valid evidence."
        ),
    },
}

_SMT_SOURCE_DESTINATIONS = {
    "claasp/cipher_modules/models/smt/smt_model.py": (
        "next/src/claasp_next/representations/constraints/smt/formula.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_cipher_model.py": (
        "next/src/claasp_next/representations/constraints/smt/lowering.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_deterministic_truncated_xor_differential_model.py": (
        "next/src/claasp_next/semantics/cryptanalysis/truncated.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_xor_differential_model.py": (
        "next/src/claasp_next/representations/constraints/smt/trails.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_xor_linear_model.py": (
        "next/src/claasp_next/representations/constraints/smt/trails.py"
    ),
    "claasp/cipher_modules/models/smt/solvers.py": (
        "next/src/claasp_next/drivers/solvers/z3.py"
    ),
    "claasp/cipher_modules/models/smt/utils/constants.py": (
        "next/src/claasp_next/drivers/solvers/z3.py"
    ),
    "claasp/cipher_modules/models/smt/utils/utils.py": (
        "next/src/claasp_next/representations/constraints/smt"
    ),
}
for _path, _destination in _SMT_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Backend-neutral SMT representations consume shared semantics, preserve provenance, "
            "and execute through the explicit Z3 driver."
        ),
        "rationale": (
            "v5 replaces backend-shaped model classes, syntax helpers, and solver registries "
            "with shared semantic problems, immutable representations, and separate drivers."
        ),
    }

MIGRATION_OVERRIDES.update({
    "tests/unit/cipher_modules/models/smt/smt_model_test.py": {
        "v5_destination": (
            "next/tests/unit/test_smt.py; next/tests/unit/test_analysis_constraints.py"
        ),
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Portable SMT serialization and shared fixed-value constraints are deterministic; "
            "solver identity is explicit driver provenance."
        ),
        "rationale": (
            "Legacy solver catalogues and exact backend assertion strings are not v5 contracts."
        ),
    },
    "tests/unit/cipher_modules/models/smt/smt_models/smt_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_z3_integration.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.4a",
        "acceptance_criterion": (
            "Z3 recovers the full Speck32/64 designers' ciphertext and graph evaluation "
            "independently verifies the assignment."
        ),
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/smt/smt_models/smt_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": (
            "Retain the proven Speck32/64-5 optimum weight 9 and independently reproduce the "
            "legacy count of 28 trails with weights 9 through 10."
        ),
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/smt/smt_models/smt_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": (
            "Preserve the Speck32/64-4 optimum weight 3, reduced three-round weights 1 and 7, "
            "and the eight Speck8/16 trails of weight at most 2."
        ),
        "rationale": None,
    },
})


_CMS_REPLACEMENTS = {
    "cms_cipher_model": "next/src/claasp_next/representations/constraints/sat/lowering.py",
    "cms_xor_linear_model": "next/src/claasp_next/representations/constraints/smt/speck.py",
    "cms_xor_differential_model": "next/src/claasp_next/representations/constraints/cp/trails.py",
    "cms_bitwise_deterministic_truncated_xor_differential_model": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
}
MIGRATION_OVERRIDES["tests/unit/cipher_modules/models/sat/sat_model_test.py"] = {
    "v5_destination": "next/tests/integration/test_minizinc_integration.py",
    "prerequisites": [],
    "disposition": "supersede",
    "status": "superseded-in-m10.8d",
    "acceptance_criterion": "Retain the zero-key Speck-3 0x00400000 -> 0x8000840A weight-3 witness, equality/inequality SAT/UNSAT boundary scenarios, and exact/truncated mixed-component feasibility; replace incidental names and mutable counter strings with shared invariants.",
    "rationale": "The fixed weight-3 witness and complete differential boundary equality/inequality SAT/UNSAT scenarios are ported through native CP constraints and independent decoding. Typed exact-prefix/truncated-suffix composition replaces the mixed Speck method-name dictionary and independently checks feasibility. Unconstrained TEA/Simon assignment names, counter internals, and mutable solver registries are representation smoke tests, not fixed scientific values; existing typed Boolean/Word witness and real-solver tests replace them while catalogue parity stays owned by M10.9d.",
}
for _module, _destination in _CMS_REPLACEMENTS.items():
    MIGRATION_OVERRIDES[f"claasp/cipher_modules/models/sat/cms_models/{_module}.py"] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared graph semantics and explicit solver drivers replace CMS-specific model subclasses; fixed CMS test evidence is separately retained.",
        "rationale": "Native XOR strings are an encoding optimization, not a distinct cryptanalytic meaning. No CryptoMiniSat execution or full catalogue coverage is claimed by this replacement; reusable missing component semantics remain owned by M10.9c.",
    }

_CMS_TEST_REPLACEMENTS = {
    "cms_cipher_model_test": ("migrate", "next/tests/integration/test_z3_integration.py", "Preserve the complete Speck32/64-22 vector 0x6574694C, 0x1918111009080100 -> 0xA86842F2 with real solving and independent evaluation."),
    "cms_xor_linear_model_test": ("migrate", "next/tests/integration/test_speck_trail_enumeration.py", "Prove Speck32/64-4 bound 2 UNSAT and bound 3 SAT; independently recount all correlations and wiring."),
    "cms_xor_differential_model_test": ("supersede", "next/tests/unit/test_cms_inventory_parity.py", "Supported full Speck32/64 differential construction is nonempty; changing the weight bound retains exact round relations and changes the explicit bound."),
    "cms_deterministic_truncated_xor_differential_model_test": ("supersede", "next/tests/unit/test_truncated_differences.py", "Typed deterministic-truncated modular-add semantics and Speck propagation replace an assertion-free construction smoke test."),
}
for _module, (_disposition, _destination, _criterion) in _CMS_TEST_REPLACEMENTS.items():
    MIGRATION_OVERRIDES[f"tests/unit/cipher_modules/models/sat/cms_models/{_module}.py"] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": _disposition,
        "status": "migrated-in-m10.8d" if _disposition == "migrate" else "superseded-in-m10.8d",
        "acceptance_criterion": _criterion,
        "rationale": None if _disposition == "migrate" else "Mutable CMS constraint counts and construction-only smoke tests are replaced by explicit immutable representation and shared-semantic invariants.",
    }


def python_paths() -> list[Path]:
    return sorted(path for root in LEGACY_ROOTS for path in root.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    with warnings.catch_warnings():
        # Legacy MiniZinc source is embedded in Python strings containing
        # backslashes that are valid MiniZinc but deprecated Python escapes.
        warnings.simplefilter("ignore", (DeprecationWarning, SyntaxWarning))
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _public_entries(tree: ast.Module) -> list[str]:
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    ]


def _dependencies(tree: ast.Module) -> list[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return sorted(names)


def _test_entries(tree: ast.Module) -> list[str]:
    return sorted(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    )


def _official_name(entries: list[str], stem: str) -> str:
    candidate = next((name for name in entries if name[:1].isupper()), "")
    for suffix in ("BlockCipher", "Permutation", "HashFunction", "StreamCipher", "Cipher"):
        if candidate.endswith(suffix):
            candidate = candidate[: -len(suffix)]
            break
    return candidate or "".join(part.capitalize() for part in stem.split("_"))


def _catalogue_metadata(relative: Path, entries: list[str]) -> dict[str, Any] | None:
    parts = relative.parts
    if len(parts) < 3 or parts[0:2] != ("claasp", "ciphers"):
        return None
    directory = parts[2]
    if directory not in CATEGORY_BY_DIRECTORY or relative.name == "__init__.py":
        return None
    official_name = _official_name(entries, relative.stem)
    high_level_parent = directory if directory in {"hash_functions", "mac", "stream_ciphers"} else None
    category = CATEGORY_BY_DIRECTORY[directory]
    return {
        "official_name": official_name,
        "primitive_category": category,
        "proposed_module": f"claasp_next.primitives.{category}.{relative.stem}",
        "proposed_class": official_name,
        "higher_level_parent": high_level_parent,
        "classification_basis": (
            "provisional fixed-length core classification; confirm bijectivity and interface during M10.9b"
            if high_level_parent
            else "legacy catalogue semantics; validate category invariant during M10.9b"
        ),
    }


def _destination(relative: Path, catalogue: dict[str, Any] | None) -> str:
    if catalogue:
        return catalogue["proposed_module"].replace(".", "/") + ".py"
    if relative.parts[0] == "tests":
        return "next/tests (mapped to the owning migrated behavior)"
    if relative.name == "__init__.py":
        return "inapplicable: package marker reviewed with its containing module"
    return "next/src/claasp_next (destination finalized by owning migration milestone)"


def _responsibility(path: Path, tree: ast.Module) -> str:
    doc = ast.get_docstring(tree, clean=True)
    if doc:
        return doc.splitlines()[0].strip()
    return path.stem.replace("_", " ")


def record(path: Path) -> dict[str, Any]:
    relative = path.relative_to(ROOT)
    tree = _parse(path)
    entries = _public_entries(tree)
    tests = _test_entries(tree)
    catalogue = _catalogue_metadata(relative, entries)
    is_marker = path.name == "__init__.py" and not entries
    kind = "test" if relative.parts[0] == "tests" else "source"
    item: dict[str, Any] = {
        "path": relative.as_posix(),
        "kind": kind,
        "responsibility": _responsibility(path, tree),
        "public_entry_points": entries,
        "dependencies": _dependencies(tree),
        "tests": tests,
        "fixed_evidence": {
            "test_functions": tests,
            "requires_fixture_review": bool(tests),
        },
        "v5_destination": _destination(relative, catalogue),
        "prerequisites": ["M10.9b"] if catalogue else ["owning migration milestone"],
        "disposition": "inapplicable" if is_marker else "migrate",
        "status": "reviewed-package-marker" if is_marker else "planned-or-partially-migrated",
        "acceptance_criterion": (
            "Containing package is represented by its non-marker entries."
            if is_marker
            else "Owning v5 behavior passes preserved legacy fixed evidence and independent semantic checks."
        ),
        "rationale": (
            "Empty package markers carry no behavior; contained modules are inventoried separately."
            if is_marker
            else None
        ),
    }
    if catalogue:
        item["primitive"] = catalogue
    item.update(MIGRATION_OVERRIDES.get(relative.as_posix(), {}))
    return item


def build_inventory() -> dict[str, Any]:
    records = [record(path) for path in python_paths()]
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": ["claasp/**/*.py", "tests/**/*.py"],
        "generated_by": "next/tools/legacy_inventory.py",
        "counts": {
            "total": len(records),
            "source": sum(item["kind"] == "source" for item in records),
            "test": sum(item["kind"] == "test" for item in records),
            "primitive": sum("primitive" in item for item in records),
        },
        "records": records,
    }


def serialized_inventory() -> str:
    return json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"


def model_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Report unresolved M10.8 model entries without treating deferrals as done."""
    records = [item for item in payload["records"] if "/models/" in item["path"]]
    unresolved = [item for item in records
                  if item["status"] == "planned-or-partially-migrated"
                  or item["disposition"] == "defer"
                  or "destination finalized" in item["v5_destination"]]
    families = {}
    for item in unresolved:
        family = item["path"].split("/models/", 1)[1].split("/", 1)[0]
        families[family] = families.get(family, 0) + 1
    return {
        "total": len(records),
        "resolved": len(records) - len(unresolved),
        "unresolved": [item["path"] for item in unresolved],
        "deferred": [item["path"] for item in unresolved if item["disposition"] == "defer"],
        "remaining_by_family": dict(sorted(families.items())),
        "complete": not unresolved,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the checked-in inventory is stale")
    parser.add_argument("--model-status", action="store_true", help="report remaining M10.8 model work without rewriting the inventory")
    parser.add_argument("--check-model-closure", action="store_true", help="fail until all M10.8 model entries are resolved, including deferrals")
    args = parser.parse_args()
    if args.model_status or args.check_model_closure:
        status = model_closure_status(build_inventory())
        print(json.dumps({key: value for key, value in status.items() if key != "unresolved"}, indent=2))
        return int(args.check_model_closure and not status["complete"])
    expected = serialized_inventory()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"legacy inventory is stale; run: python {Path(__file__).name}")
            return 1
        print(f"legacy inventory covers {build_inventory()['counts']['total']} Python files")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
