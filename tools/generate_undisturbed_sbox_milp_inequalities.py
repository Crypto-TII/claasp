#!/usr/bin/env python3
"""Generate legacy undisturbed-bit S-box product-of-sums clauses.

The offline generator reconstructs the per-output-bit Espresso formulation
from the complete typed ternary relation. Generated JSON has no runtime
Espresso dependency.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from itertools import product
from pathlib import Path

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    TruncatedBit,
    TruncatedXorDifference,
)

LEGACY_COMMIT = "3aacc2758059de85682a9c6d0eda2cd75940e747"
LEGACY_PATH = (
    "claasp/cipher_modules/models/milp/utils/generate_undisturbed_bits_inequalities_for_sboxes.py"
)


def _table(value: str) -> tuple[int, ...]:
    table = tuple(int(item, 0) for item in value.split(","))
    if not table or len(table) & (len(table) - 1):
        raise argparse.ArgumentTypeError("table length must be a power of two")
    return table


def _encoded(bits) -> str:
    return "".join(f"{bit.encoded:02b}" for bit in bits)


def _espresso(rows: tuple[str, ...], width: int) -> tuple[str, ...]:
    source = [f".i {width}", ".o 1", *(f"{row} 1" for row in rows), ".e"]
    completed = subprocess.run(
        ["espresso", "-epos"],
        input="\n".join(source) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    patterns = tuple(
        sorted(
            {
                fields[0]
                for line in completed.stdout.splitlines()
                for fields in (line.split(),)
                if len(fields) == 2 and len(fields[0]) == width and set(fields[0]) <= set("01-")
            }
        )
    )
    if not patterns:
        raise RuntimeError("Espresso returned no product-of-sums clauses")
    accepted = set(rows)
    for values in product("01", repeat=width):
        point = "".join(values)
        excluded = any(
            all(symbol == "-" or symbol == value for symbol, value in zip(pattern, point))
            for pattern in patterns
        )
        if excluded is (point in accepted):
            raise RuntimeError("Espresso clauses disagree with the projected relation")
    return patterns


def generate(table: tuple[int, ...], name: str) -> dict[str, object]:
    semantics = SBoxTransitionSemantics(table)
    symbols = (TruncatedBit.ZERO, TruncatedBit.ONE, TruncatedBit.UNKNOWN)
    transitions = []
    for inputs in product(symbols, repeat=semantics.width):
        source = TruncatedXorDifference(inputs)
        transitions.append((source, semantics.truncated_xor_differential(source)))
    systems = []
    for position in range(semantics.width):
        for encoding_bit in range(2):
            rows = tuple(
                _encoded(source.bits) + f"{output.bits[position].encoded:02b}"[encoding_bit]
                for source, output in transitions
            )
            systems.append(
                {
                    "output_position": position,
                    "encoding_bit": encoding_bit,
                    "clauses": list(_espresso(rows, 2 * semantics.width + 1)),
                }
            )
    return {
        "schema_version": 1,
        "name": name,
        "table": list(table),
        "legacy_source": {"commit": LEGACY_COMMIT, "path": LEGACY_PATH},
        "generator": {"tool": "espresso", "arguments": ["-epos"]},
        "systems": systems,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--table", type=_table)
    source.add_argument("--builtin", choices=("present",))
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    table = PRESENT_SBOX if arguments.builtin == "present" else arguments.table
    payload = generate(table, arguments.name)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
