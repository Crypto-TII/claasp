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
        "prerequisites": ["M10.9b toy primitive classification", "M10.9d toy Speck8/16", "M10.8d nonzero key-mask composition"],
        "disposition": "defer",
        "status": "partially-migrated-in-m10.8d",
        "acceptance_criterion": (
            "Preserve the Speck32/64-4 optimum weight 3, reduced three-round weights 1 and 7, "
            "and the eight Speck8/16 trails of weight at most 2."
        ),
        "rationale": (
            "The four-round optimum has exact shared semantics and independent checking; the "
            "three-round optimum 1 and feasible weight 7 are restored by graph-wired Z3 models. "
            "Only the Speck8/16 count remains: its nonstandard toy graph and nonzero key-mask "
            "propagation are prerequisites beyond the existing zero-key data-path model."
        ),
    },
})


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the checked-in inventory is stale")
    args = parser.parse_args()
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
