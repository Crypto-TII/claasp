#!/usr/bin/env python3
"""Generate exact small-S-box MILP inequality systems with Sage.

Run this tool with Sage's Python, not the dependency-free CLAASP interpreter::

    sage -python tools/generate_sbox_milp_inequalities.py \
        --name present --table 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 \
        --output present_sbox_milp_inequalities.json

The output contains full convex-hull facets and the legacy greedy and
minimum-cardinality reductions for differential and signed-linear classes.
"""

from __future__ import annotations

import argparse
import importlib
import json
from functools import reduce
from math import gcd
from pathlib import Path

LEGACY_COMMIT = "3aacc2758059de85682a9c6d0eda2cd75940e747"
LEGACY_PATH = (
    "claasp/cipher_modules/models/milp/utils/generate_sbox_inequalities_for_trail_search.py"
)


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


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> bit) & 1 for bit in reversed(range(width)))


def _integer_inequality(values) -> tuple[int, ...]:
    lcm = importlib.import_module("sage.arith.functions").lcm

    scale = int(lcm([item.denominator() for item in values]))
    integers = [int(item * scale) for item in values]
    common = reduce(gcd, (abs(item) for item in integers if item), 0) or 1
    return tuple(item // common for item in integers)


def _facets(points: list[tuple[int, ...]]) -> tuple[tuple[int, ...], ...]:
    polyhedron_type = importlib.import_module("sage.geometry.polyhedron.constructor").Polyhedron

    polyhedron = polyhedron_type(vertices=points)
    return tuple(sorted(_integer_inequality(tuple(item)) for item in polyhedron.inequalities()))


def _contains(inequality: tuple[int, ...], point: tuple[int, ...]) -> bool:
    return inequality[0] + sum(a * x for a, x in zip(inequality[1:], point)) >= 0


def _greedy(
    facets: tuple[tuple[int, ...], ...],
    valid: set[tuple[int, ...]],
    width: int,
) -> tuple[tuple[int, ...], ...]:
    impossible = {
        _bits(value, width) for value in range(1 << width) if _bits(value, width) not in valid
    }
    remaining = set(facets)
    chosen = []
    while impossible:
        if not remaining:
            raise RuntimeError("facets do not exclude every impossible point")
        inequality = max(
            remaining,
            key=lambda item: (sum(not _contains(item, point) for point in impossible), item),
        )
        chosen.append(inequality)
        remaining.remove(inequality)
        impossible = {point for point in impossible if _contains(inequality, point)}
    return tuple(chosen)


def _minimum(
    facets: tuple[tuple[int, ...], ...],
    valid: set[tuple[int, ...]],
    width: int,
) -> tuple[tuple[int, ...], ...]:
    mixed_integer_linear_program = importlib.import_module(
        "sage.numerical.mip"
    ).MixedIntegerLinearProgram

    impossible = tuple(
        _bits(value, width) for value in range(1 << width) if _bits(value, width) not in valid
    )
    cuts = tuple(
        tuple(index for index, point in enumerate(impossible) if not _contains(facet, point))
        for facet in facets
    )
    model = mixed_integer_linear_program(maximization=False, solver="GLPK")
    selected = model.new_variable(binary=True, name="selected")
    model.set_objective(sum(selected[index] for index in range(len(facets))))
    for point_index in range(len(impossible)):
        candidates = [selected[index] for index, cut in enumerate(cuts) if point_index in cut]
        if not candidates:
            raise RuntimeError("facets do not exclude every impossible point")
        model.add_constraint(sum(candidates) >= 1)
    model.solve()
    values = model.get_values(selected)
    return tuple(facet for index, facet in enumerate(facets) if round(values[index]) == 1)


def _system(table: tuple[int, ...], kind: str) -> dict[str, object]:
    width = len(table).bit_length() - 1
    counts = _counts(table, kind)
    classes: dict[int, list[tuple[int, ...]]] = {}
    for source, row in enumerate(counts):
        for target, count in enumerate(row):
            if count and (source or target):
                classes.setdefault(count, []).append(_bits(source, width) + _bits(target, width))
    groups = []
    for count, points in sorted(classes.items()):
        valid = set(points)
        facets = _facets(points)
        groups.append(
            {
                "transition_count": count,
                "point_count": len(points),
                "inequalities": {
                    "convex_hull": [list(item) for item in facets],
                    "greedy": [list(item) for item in _greedy(facets, valid, 2 * width)],
                    "minimum": [list(item) for item in _minimum(facets, valid, 2 * width)],
                },
            }
        )
    return {"kind": kind, "groups": groups}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--table", required=True, type=_table)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    payload = {
        "schema_version": 1,
        "name": arguments.name,
        "table": list(arguments.table),
        "legacy_source": {"commit": LEGACY_COMMIT, "path": LEGACY_PATH},
        "systems": [
            _system(arguments.table, "xor_differential"),
            _system(arguments.table, "xor_linear"),
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
