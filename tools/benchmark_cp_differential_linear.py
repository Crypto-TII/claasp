#!/usr/bin/env python3
"""Benchmark portable deterministic-middle differential-linear MiniZinc."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import Speck
from claasp.representations.constraints.cp import WordDeterministicDifferentialLinearCPModel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds = []
    model = query = None
    for _ in range(args.repeats):
        started = monotonic()
        model = WordDeterministicDifferentialLinearCPModel(
            Speck(number_of_rounds=3),
            prefix_rounds=1,
            middle_rounds=1,
            differential_maximum_weight=16,
            linear_maximum_weight=16,
        )
        query = model.cp_model()
        builds.append(monotonic() - started)
    assert model is not None and query is not None
    solver = MiniZincSolver(solver="chuffed", timeout_seconds=30)
    results = [solver.solve(query) for _ in range(args.repeats)]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError("Chuffed did not solve")
    trails = [model.decode_trail(result.assignment) for result in results]
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "Speck32/64-3 deterministic-middle differential-linear composition",
            "timeout_seconds": 30,
        },
        "result": {
            "solver": "MiniZincSolver/chuffed",
            "repeats": args.repeats,
            "variables": len(query.declarations),
            "constraints": len(query.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(result.runtime_seconds for result in results),
            "solver_status": CPStatus.SATISFIED.value,
            "assignment_valid": all(trail.linear.output_mask != 0 for trail in trails),
            "peak_memory_bytes_median": None,
            "peak_memory_status": "not_reported_by_minizinc_driver",
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
