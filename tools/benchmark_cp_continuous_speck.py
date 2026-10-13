#!/usr/bin/env python3
"""Benchmark fixed-input continuous Speck propagation through MiniZinc."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.representations.constraints.cp import SpeckContinuousHeuristicCPModel
from claasp.semantics.cryptanalysis import continuous_speck32


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    left = (-1.0, -1.0, -1.0, 1.0) + (-1.0,) * 12
    right = (-1.0, 1.0, -1.0, 1.0) + (-1.0,) * 12
    expected = continuous_speck32(left, right, rounds=2).values
    builds, solves, errors = [], [], []
    query = None
    for _ in range(args.repeats):
        started = monotonic()
        model = SpeckContinuousHeuristicCPModel(left, right, rounds=2)
        query = model.cp_model()
        builds.append(monotonic() - started)
        solved = MiniZincSolver(solver="gecode", timeout_seconds=30).solve(query)
        if solved.status is not CPStatus.SATISFIED:
            raise RuntimeError("Gecode did not return a numerical candidate")
        result = model.decode_result(solved.assignment)
        errors.append(max(abs(a - b) for a, b in zip(result.values, expected)))
        solves.append(solved.runtime_seconds)
    assert query is not None
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {"description": "fixed-input two-round continuous Speck32 heuristic"},
        "result": {
            "solver": "MiniZinc/Gecode",
            "repeats": args.repeats,
            "declarations": len(query.declarations),
            "constraints": len(query.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(solves),
            "maximum_python_parity_error": max(errors),
            "claim_kind": "heuristic",
            "solver_status": CPStatus.SATISFIED.value,
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
