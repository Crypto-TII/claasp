"""Audit a CLAASP v5 wheel for owned package data and development-artifact leaks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

REQUIRED = {
    "claasp_next/catalogue/data/catalogue.json",
    "claasp_next/primitives/permutations/poseidon/data/poseidon_bn254_width3.json",
    "claasp_next/primitives/_catalogue_exports.py",
    "claasp_next/serialization/primitive.py",
    "claasp_next/representations/source/__init__.py",
}
FORBIDDEN_PARTS = {
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "migration",
    "tests",
    "tools",
}
FORBIDDEN_NAMES = {
    "m10_16_public_api.json",
    "m10_16_typing_baseline.json",
    "pyproject.toml",
}
FORBIDDEN_SUFFIXES = {".a", ".c", ".dll", ".dylib", ".h", ".o", ".pyc", ".so"}


def audit_entries(entries: list[str]) -> list[str]:
    """Return deterministic wheel-ownership violations."""

    names = set(entries)
    violations = [f"missing required wheel entry: {name}" for name in sorted(REQUIRED - names)]
    for name in sorted(names):
        path = PurePosixPath(name)
        if FORBIDDEN_PARTS.intersection(path.parts):
            violations.append(f"development-only path shipped: {name}")
        if path.name in FORBIDDEN_NAMES:
            violations.append(f"development-only file shipped: {name}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            violations.append(f"binary, cache, or legacy native source shipped: {name}")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args(argv)
    with ZipFile(args.wheel) as archive:
        entries = archive.namelist()
    violations = audit_entries(entries)
    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1
    print(f"wheel audit passes: {len(entries)} entries, no development artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
