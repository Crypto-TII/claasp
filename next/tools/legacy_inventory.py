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
