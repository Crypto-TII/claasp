"""Import a pinned Poseidon parameter set without executing upstream code.

This development tool reads literal assignments from the MIT-licensed
``ingonyama-zk/poseidon-hash`` reference implementation and writes the narrow
JSON schema consumed by :mod:`claasp_next.parameters`.

Usage::

    python tools/import_poseidon_reference.py \
        /path/to/poseidon-hash/poseidon/parameters.py \
        src/claasp_next/primitives/permutations/poseidon/data/poseidon_bn254_width3.json
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

SOURCE_URL = "https://github.com/ingonyama-zk/poseidon-hash"
SOURCE_COMMIT = "5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d"
REFERENCE_OUTPUT = "0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29"


def _literal_assignments(source: Path, names: set[str]) -> dict[str, object]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    assignments: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in names:
            assignments[target.id] = ast.literal_eval(node.value)
    missing = names - assignments.keys()
    if missing:
        raise ValueError(f"upstream parameter file is missing assignments: {sorted(missing)}")
    return assignments


def import_parameters(source: Path) -> dict[str, object]:
    values = _literal_assignments(source, {"prime_254", "round_constants_254", "matrix_254"})
    width = 3
    full_rounds = 8
    partial_rounds = 57
    flat_constants = tuple(int(value, 16) for value in values["round_constants_254"])
    expected_constants = width * (full_rounds + partial_rounds)
    if len(flat_constants) != expected_constants:
        raise ValueError(f"expected {expected_constants} round constants, got {len(flat_constants)}")

    return {
        "schema_version": 1,
        "name": "poseidon_bn254_width3",
        "source": {
            "url": SOURCE_URL,
            "commit": SOURCE_COMMIT,
            "license": "MIT",
            "upstream_symbols": ["prime_254", "round_constants_254", "matrix_254"],
        },
        "modulus": values["prime_254"],
        "width": width,
        "exponent": 5,
        "full_rounds": full_rounds,
        "partial_rounds": partial_rounds,
        "round_constants": [
            list(flat_constants[offset : offset + width])
            for offset in range(0, len(flat_constants), width)
        ],
        "linear_layer": [
            [int(value, 16) for value in row]
            for row in values["matrix_254"]
        ],
        "reference": {
            "input": [0, 1, 2],
            "output_position": 1,
            "output": int(REFERENCE_OUTPUT, 16),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    payload = import_parameters(arguments.source)
    arguments.destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
