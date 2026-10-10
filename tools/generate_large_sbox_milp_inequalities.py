#!/usr/bin/env python3
"""Generate exact large-S-box MILP product-of-sums systems with Espresso.

Run this offline tool in an environment containing the UC Berkeley Espresso
executable. The generated bundle has no runtime Espresso dependency::

    PYTHONPATH=src python tools/generate_large_sbox_milp_inequalities.py \
        --name aes --builtin aes --output aes_sbox_milp_inequalities.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from claasp.composites.aes import AES_SBOX

LEGACY_COMMIT = "3aacc2758059de85682a9c6d0eda2cd75940e747"
LEGACY_PATH = "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_large_sboxes.py"


def _table(value: str) -> tuple[int, ...]:
    table = tuple(int(item, 0) for item in value.split(","))
    if not table or len(table) & (len(table) - 1):
        raise argparse.ArgumentTypeError("table length must be a power of two")
    if sorted(table) != list(range(len(table))):
        raise argparse.ArgumentTypeError("table must be a permutation")
    return table


def _counts(table: tuple[int, ...], kind: str) -> tuple[tuple[int, ...], ...]:
    size = len(table)
    if kind == "xor_differential":
        return tuple(
            tuple(
                sum((table[x] ^ table[x ^ source]) == target for x in range(size))
                for target in range(size)
            )
            for source in range(size)
        )
    return tuple(
        tuple(
            sum(
                1 if ((source & x).bit_count() ^ (target & table[x]).bit_count()) & 1 == 0 else -1
                for x in range(size)
            )
            for target in range(size)
        )
        for source in range(size)
    )


def _clause(pattern: str) -> list[int]:
    coefficients = [1 if item == "0" else -1 if item == "1" else 0 for item in pattern]
    return [coefficients.count(-1) - 1, *coefficients]


def _espresso(matrix: tuple[tuple[int, ...], ...], count: int, width: int) -> list[list[int]]:
    rows = [f".i {2 * width}", ".o 1"]
    for source, values in enumerate(matrix):
        for target, value in enumerate(values):
            point = f"{source:0{width}b}{target:0{width}b}"
            rows.append(f"{point} {int(bool(source or target) and value == count)}")
    rows.append(".e")
    result = subprocess.run(
        ["espresso", "-epos"],
        input="\n".join(rows) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    patterns = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and len(fields[0]) == 2 * width and set(fields[0]) <= set("01-"):
            patterns.append(fields[0])
    if not patterns:
        raise RuntimeError(f"Espresso returned no clauses for transition count {count}")
    return [_clause(pattern) for pattern in sorted(set(patterns))]


def _system(table: tuple[int, ...], kind: str) -> dict[str, object]:
    matrix = _counts(table, kind)
    width = len(table).bit_length() - 1
    counts = sorted(
        {
            value
            for source, row in enumerate(matrix)
            for target, value in enumerate(row)
            if value and (source or target)
        }
    )
    return {
        "kind": kind,
        "groups": [
            {
                "transition_count": count,
                "point_count": sum(value == count for row in matrix for value in row),
                "inequalities": {"espresso": _espresso(matrix, count, width)},
            }
            for count in counts
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    table_source = parser.add_mutually_exclusive_group(required=True)
    table_source.add_argument("--table", type=_table)
    table_source.add_argument("--builtin", choices=("aes",))
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    table = AES_SBOX if arguments.builtin == "aes" else arguments.table
    if len(table) > 256:
        parser.error("large-S-box Espresso generation currently supports at most 8 bits")
    payload = {
        "schema_version": 1,
        "name": arguments.name,
        "table": list(table),
        "legacy_source": {"commit": LEGACY_COMMIT, "path": LEGACY_PATH},
        "generator": {"tool": "espresso", "arguments": ["-epos"]},
        "systems": [
            _system(table, "xor_differential"),
            _system(table, "xor_linear"),
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
