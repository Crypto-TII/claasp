#!/usr/bin/env python3
"""Generate recovered wordwise XOR and truncated-MDS Espresso clauses."""

from __future__ import annotations

import argparse
import json
import subprocess
from itertools import product
from pathlib import Path

from claasp.semantics.cryptanalysis import (
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    propagate_dense_wordwise_activity,
)

LEGACY_COMMIT = "3aacc2758059de85682a9c6d0eda2cd75940e747"
LEGACY_PATHS = (
    "claasp/cipher_modules/models/milp/utils/"
    "generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits.py",
    "claasp/cipher_modules/models/milp/utils/"
    "generate_inequalities_for_wordwise_truncated_mds_matrices.py",
)


def _differences(width: int) -> tuple[WordwiseXorDifference, ...]:
    return (
        WordwiseXorDifference(width, WordwiseDifferenceKind.ZERO),
        *(WordwiseXorDifference.known(width, value) for value in range(1, 1 << width)),
        WordwiseXorDifference(width, WordwiseDifferenceKind.NONZERO),
        WordwiseXorDifference(width, WordwiseDifferenceKind.UNKNOWN),
    )


def _encode(difference: WordwiseXorDifference, *, include_value: bool) -> tuple[int, ...]:
    kind = difference.kind.value
    encoded = (kind >> 1, kind & 1)
    if not include_value:
        return encoded
    value = difference.value if difference.kind is WordwiseDifferenceKind.KNOWN else 0
    assert value is not None
    return (*encoded, *(value >> bit & 1 for bit in reversed(range(difference.width))))


def _from_kind(width: int, kind: WordwiseDifferenceKind) -> WordwiseXorDifference:
    return (
        WordwiseXorDifference.known(width, 1)
        if kind is WordwiseDifferenceKind.KNOWN
        else WordwiseXorDifference(width, kind)
    )


def xor_rows(width: int, operands: int) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(bit for item in inputs for bit in _encode(item, include_value=True))
        + _encode(WordwiseXorDifference.xor_many(inputs), include_value=True)
        for inputs in product(_differences(width), repeat=operands)
    )


def mds_rows(width: int, inputs: int, outputs: int) -> tuple[tuple[int, ...], ...]:
    kinds = tuple(WordwiseDifferenceKind)
    return tuple(
        tuple(bit for kind in input_kinds for bit in _encode(_from_kind(width, kind), include_value=False))
        + tuple(
            bit
            for item in propagate_dense_wordwise_activity(
                tuple(_from_kind(width, kind) for kind in input_kinds), outputs
            )
            for bit in _encode(item, include_value=False)
        )
        for input_kinds in product(kinds, repeat=inputs)
    )


def _espresso(rows: tuple[tuple[int, ...], ...]) -> tuple[str, ...]:
    width = len(rows[0])
    source = [f".i {width}", ".o 1", *(f"{''.join(map(str, row))} 1" for row in rows), ".e"]
    completed = subprocess.run(
        ["espresso", "-epos"], input="\n".join(source) + "\n", text=True, capture_output=True, check=True
    )
    clauses = tuple(
        sorted(
            {
                fields[0]
                for line in completed.stdout.splitlines()
                for fields in (line.split(),)
                if len(fields) == 2 and len(fields[0]) == width and set(fields[0]) <= set("01-")
            }
        )
    )
    accepted = set(rows)
    for values in product((0, 1), repeat=width):
        excluded = any(
            all(symbol == "-" or int(symbol) == value for symbol, value in zip(clause, values))
            for clause in clauses
        )
        if excluded is (values in accepted):
            raise RuntimeError("Espresso clauses disagree with the recovered relation")
    return clauses


def generate(width: int, operands: int, dimensions: tuple[int, int]) -> dict[str, object]:
    xor = xor_rows(width, operands)
    mds = mds_rows(width, dimensions[1], dimensions[0])
    return {
        "schema_version": 1,
        "legacy_source": {"commit": LEGACY_COMMIT, "paths": list(LEGACY_PATHS)},
        "generator": {"tool": "espresso", "arguments": ["-epos"]},
        "word_width": width,
        "xor": {"operands": operands, "row_count": len(xor), "clauses": list(_espresso(xor))},
        "mds": {"dimensions": list(dimensions), "row_count": len(mds), "clauses": list(_espresso(mds))},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--word-width", type=int, default=4)
    parser.add_argument("--xor-operands", type=int, default=2)
    parser.add_argument("--mds-dimensions", default="4x4")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    rows, columns = (int(value) for value in arguments.mds_dimensions.split("x", 1))
    payload = generate(arguments.word_width, arguments.xor_operands, (rows, columns))
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
