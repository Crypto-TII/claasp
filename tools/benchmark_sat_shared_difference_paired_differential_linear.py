#!/usr/bin/env python3
"""Benchmark the recovered paired-input differential-linear SAT formula."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import KissatSolver, MinisatSolver, SatStatus
from claasp.primitives import Speck
from claasp.representations.constraints.sat import (
    SharedDifferencePairedWordDifferentialLinearSATModel,
)


def _benchmark(solver_type, repeats):
    build_times = []
    model = formula = None
    for _ in range(repeats):
        started = monotonic()
        model = SharedDifferencePairedWordDifferentialLinearSATModel(
            Speck(number_of_rounds=3),
            prefix_rounds=2,
            paired_differential_maximum_weight=32,
            linear_maximum_weight=16,
            fixed_total_weight=8,
        )
        formula = model.cnf_formula()
        build_times.append(monotonic() - started)
    assert model is not None and formula is not None
    results = [solver_type(timeout_seconds=30).solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{solver_type.__name__} did not solve")
    trails = [model.decode_trail(result.assignment) for result in results]
    return {
        "solver": solver_type.__name__,
        "repeats": repeats,
        "variables": formula.variable_count,
        "clauses": formula.clause_count,
        "literals": formula.literal_count,
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": all(trail.total_weight == 8 for trail in trails),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_sat_drivers",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    payload = {
        "schema_version": 1,
        "workload": {
            "description": "Speck32/64-3 paired-input differential-linear trail at fixed weight 8",
            "comparison": "identical formula, restrictions, settings, and host",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(solver_type, arguments.repeats)
            for solver_type in (MinisatSolver, KissatSolver)
        ],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
