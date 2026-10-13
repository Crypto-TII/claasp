#!/usr/bin/env python3
"""Benchmark direct and exhaustive differential-linear SAT boundary CNFs."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from itertools import product
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver, SatStatus
from claasp.representations.constraints.sat import (
    CNFFormula,
    DifferentialToTruncatedSATModel,
    TruncatedToLinearSATModel,
)


def _forbidden_assignment_formula(kind: str, width: int) -> CNFFormula:
    variables = tuple(
        name
        for bit in range(width)
        for name in (
            (f"difference_{bit}", f"truncated_{bit}_unknown", f"truncated_{bit}_value")
            if kind == "upper"
            else (f"truncated_{bit}_unknown", f"truncated_{bit}_value", f"mask_{bit}")
        )
    )
    indices = {name: index + 1 for index, name in enumerate(variables)}
    clauses = []
    for bit in range(width):
        names = (
            (f"difference_{bit}", f"truncated_{bit}_unknown", f"truncated_{bit}_value")
            if kind == "upper"
            else (f"truncated_{bit}_unknown", f"truncated_{bit}_value", f"mask_{bit}")
        )
        for first, second, third in product((0, 1), repeat=3):
            allowed = (
                not second and third == first
                if kind == "upper"
                else not (first and second) and not (first and third)
            )
            if not allowed:
                clauses.append(
                    tuple(
                        -indices[name] if value else indices[name]
                        for name, value in zip(names, (first, second, third))
                    )
                )
    return CNFFormula(variables, tuple(clauses), ("exhaustive_boundary",) * len(clauses))


def _formula(strategy: str, kind: str, width: int):
    if strategy == "portable_forbidden_assignment":
        return _forbidden_assignment_formula(kind, width)
    if kind == "upper":
        return DifferentialToTruncatedSATModel(width).cnf_formula()
    return TruncatedToLinearSATModel(width).cnf_formula()


def _fixed(kind: str, width: int):
    bits = tuple(bit % 2 for bit in range(width))
    if kind == "upper":
        return {
            name: value
            for bit, value in enumerate(bits)
            for name, value in (
                (f"difference_{bit}", value),
                (f"truncated_{bit}_unknown", 0),
                (f"truncated_{bit}_value", value),
            )
        }
    return {
        name: value
        for bit, value in enumerate(bits)
        for name, value in (
            (f"truncated_{bit}_unknown", value),
            (f"truncated_{bit}_value", 0),
            (f"mask_{bit}", 0),
        )
    }


def _benchmark(strategy: str, kind: str, solver_type, repeats: int, width: int):
    build_times = []
    formula = None
    for _ in range(repeats):
        started = monotonic()
        formula = _formula(strategy, kind, width)
        build_times.append(monotonic() - started)
    assert formula is not None
    fixed = _fixed(kind, width)
    results = [solver_type(timeout_seconds=30).solve(formula, fixed) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{strategy}/{kind}/{solver_type.__name__} did not solve")
    if any(not formula.is_satisfied(result.assignment) for result in results):
        raise RuntimeError("solver returned an invalid assignment")
    return {
        "strategy": strategy,
        "boundary": kind,
        "solver": solver_type.__name__,
        "repeats": repeats,
        "variables": formula.variable_count,
        "clauses": formula.clause_count,
        "literals": formula.literal_count,
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": True,
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_sat_drivers",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--width", type=int, default=32)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0 or arguments.width <= 0:
        parser.error("--repeats and --width must be positive")
    results = [
        _benchmark(strategy, kind, solver_type, arguments.repeats, arguments.width)
        for kind in ("upper", "lower")
        for strategy in ("portable_forbidden_assignment", "recovered_direct")
        for solver_type in (MinisatSolver, KissatSolver, CryptoMiniSatSolver)
    ]
    payload = {
        "schema_version": 1,
        "workload": {
            "description": f"fixed {arguments.width}-bit differential-linear boundary",
            "timeout_seconds": 30,
            "comparison": "same truth table, assignment, solvers, settings, and host",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": results,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
