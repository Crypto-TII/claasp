#!/usr/bin/env python3
"""Generate exact small-S-box MILP inequality systems with cddlib and GLPK.

The generator uses cddlib's exact GMP executable for convex-hull conversion
and GLPK for minimum-cardinality set cover. The generated constraints have no
cddlib dependency at runtime; GLPK is also available separately as an optional
runtime solver. Both tools are pinned in the canonical development image::

    python tools/generate_sbox_milp_inequalities.py \
        --name present --table 12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2 \
        --output present_sbox_milp_inequalities.json

The output contains full convex-hull facets and the legacy greedy and
minimum-cardinality reductions for differential and signed-linear classes.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from fractions import Fraction
from functools import reduce
from math import gcd, lcm
from pathlib import Path
from tempfile import TemporaryDirectory

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


def _integer_inequality(values: tuple[Fraction, ...]) -> tuple[int, ...]:
    scale = lcm(*(item.denominator for item in values))
    integers = [int(item * scale) for item in values]
    common = reduce(gcd, (abs(item) for item in integers if item), 0) or 1
    return tuple(item // common for item in integers)


def _resolve_executable(executable: str) -> str:
    resolved = shutil.which(executable)
    if resolved is None:
        raise FileNotFoundError(f"required executable {executable!r} was not found")
    return resolved


def _cdd_v_representation(points: list[tuple[int, ...]]) -> str:
    if not points or not points[0]:
        raise ValueError("convex-hull points must be nonempty")
    dimension = len(points[0])
    if any(len(point) != dimension for point in points):
        raise ValueError("convex-hull points must have one common dimension")
    rows = "\n".join(f"1 {' '.join(map(str, point))}" for point in points)
    return f"V-representation\nbegin\n{len(points)} {dimension + 1} rational\n{rows}\nend\n"


def _parse_cdd_h_representation(text: str) -> tuple[tuple[int, ...], ...]:
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    try:
        header = lines.index("H-representation")
        begin = lines.index("begin", header)
    except ValueError as error:
        raise RuntimeError("cddlib did not return an H-representation") from error
    linearity: set[int] = set()
    for line in lines[header + 1 : begin]:
        fields = line.split()
        if fields and fields[0] == "linearity":
            count = int(fields[1])
            linearity.update(int(value) for value in fields[2:])
            if len(linearity) != count:
                raise RuntimeError("cddlib returned malformed linearity metadata")
    shape = lines[begin + 1].split()
    if len(shape) != 3 or shape[2] != "rational":
        raise RuntimeError("cddlib returned an unsupported H-representation shape")
    row_count, column_count = map(int, shape[:2])
    raw_rows = lines[begin + 2 : begin + 2 + row_count]
    if len(raw_rows) != row_count:
        raise RuntimeError("cddlib returned an incomplete H-representation")
    inequalities = []
    for index, line in enumerate(raw_rows, 1):
        values = tuple(Fraction(value) for value in line.split())
        if len(values) != column_count:
            raise RuntimeError("cddlib returned an H-representation row of the wrong width")
        inequality = _integer_inequality(values)
        inequalities.append(inequality)
        if index in linearity:
            inequalities.append(tuple(-value for value in inequality))
    return tuple(sorted(set(inequalities)))


def _facets(
    points: list[tuple[int, ...]], executable: str = "cddexec_gmp"
) -> tuple[tuple[int, ...], ...]:
    completed = subprocess.run(
        [_resolve_executable(executable), "--rep"],
        input=_cdd_v_representation(points),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"cddlib failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return _parse_cdd_h_representation(completed.stdout)


def _set_cover_lp(cuts: tuple[tuple[int, ...], ...], point_count: int) -> str:
    variables = tuple(f"selected_{index}" for index in range(len(cuts)))
    lines = ["Minimize", f" objective: {' + '.join(variables)}", "Subject To"]
    for point_index in range(point_count):
        candidates = tuple(variables[index] for index, cut in enumerate(cuts) if point_index in cut)
        if not candidates:
            raise RuntimeError("facets do not exclude every impossible point")
        lines.append(f" cover_{point_index}: {' + '.join(candidates)} >= 1")
    lines.extend(("Binary", f" {' '.join(variables)}", "End"))
    return "\n".join(lines) + "\n"


def _parse_glpk_selected(text: str, variable_count: int) -> tuple[int, ...]:
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    statuses = tuple(line for line in lines if line.startswith("s mip "))
    if len(statuses) != 1 or statuses[0].split()[4] != "o":
        raise RuntimeError("GLPK did not return an optimal set cover")
    selected = []
    for line in lines:
        fields = line.split()
        if fields and fields[0] == "j" and int(fields[2]) == 1:
            index = int(fields[1]) - 1
            if index < 0 or index >= variable_count:
                raise RuntimeError("GLPK selected an unknown set-cover variable")
            selected.append(index)
    return tuple(selected)


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
    executable: str = "glpsol",
) -> tuple[tuple[int, ...], ...]:
    impossible = tuple(
        _bits(value, width) for value in range(1 << width) if _bits(value, width) not in valid
    )
    cuts = tuple(
        tuple(index for index, point in enumerate(impossible) if not _contains(facet, point))
        for facet in facets
    )
    with TemporaryDirectory(prefix="claasp-sbox-cover-") as directory:
        model_path = Path(directory) / "cover.lp"
        solution_path = Path(directory) / "cover.sol"
        model_path.write_text(_set_cover_lp(cuts, len(impossible)), encoding="ascii")
        completed = subprocess.run(
            [
                _resolve_executable(executable),
                "--lp",
                str(model_path),
                "--write",
                str(solution_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0 or not solution_path.is_file():
            raise RuntimeError(
                f"GLPK failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        selected = _parse_glpk_selected(solution_path.read_text(encoding="ascii"), len(facets))
    return tuple(facets[index] for index in selected)


def _system(
    table: tuple[int, ...], kind: str, cdd_executable: str, glpsol_executable: str
) -> dict[str, object]:
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
        facets = _facets(points, cdd_executable)
        groups.append(
            {
                "transition_count": count,
                "point_count": len(points),
                "inequalities": {
                    "convex_hull": [list(item) for item in facets],
                    "greedy": [list(item) for item in _greedy(facets, valid, 2 * width)],
                    "minimum": [
                        list(item)
                        for item in _minimum(facets, valid, 2 * width, executable=glpsol_executable)
                    ],
                },
            }
        )
    return {"kind": kind, "groups": groups}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--table", required=True, type=_table)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cdd-executable", default="cddexec_gmp")
    parser.add_argument("--glpsol-executable", default="glpsol")
    arguments = parser.parse_args()
    payload = {
        "schema_version": 1,
        "name": arguments.name,
        "table": list(arguments.table),
        "legacy_source": {"commit": LEGACY_COMMIT, "path": LEGACY_PATH},
        "systems": [
            _system(
                arguments.table,
                "xor_differential",
                arguments.cdd_executable,
                arguments.glpsol_executable,
            ),
            _system(
                arguments.table,
                "xor_linear",
                arguments.cdd_executable,
                arguments.glpsol_executable,
            ),
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
