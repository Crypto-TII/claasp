#!/usr/bin/env python3
"""Benchmark exact modular-add boomerang feasibility in MiniZinc."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.representations.constraints.cp import ModularAddBoomerangCPModel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds, solves = [], []
    query = connectivity = None
    for _ in range(args.repeats):
        started = monotonic()
        model = ModularAddBoomerangCPModel(
            16, delta_left=1, delta_right=0, nabla_output=1, nabla_right=0
        )
        query = model.cp_model()
        builds.append(monotonic() - started)
        solved = MiniZincSolver(solver="chuffed", timeout_seconds=30).solve(query)
        if solved.status is not CPStatus.SATISFIED:
            raise RuntimeError("Chuffed did not find the reviewed switch")
        connectivity = model.decode_connectivity(solved.assignment)
        solves.append(solved.runtime_seconds)
    assert query is not None and connectivity is not None
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {"description": "fixed 16-bit modular-add boomerang switch"},
        "result": {
            "solver": "MiniZinc/Chuffed",
            "repeats": args.repeats,
            "declarations": len(query.declarations),
            "constraints": len(query.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(solves),
            "quartet_count": connectivity.count,
            "assignment_valid": connectivity.is_possible,
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
