#!/usr/bin/env python3
"""Benchmark portable semi-deterministic truncated Speck MILP."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Speck
from claasp.representations.constraints.milp import (
    SpeckSemiDeterministicTruncatedMILPModel,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds = []
    model = formulation = None
    for _ in range(args.repeats):
        started = monotonic()
        model = SpeckSemiDeterministicTruncatedMILPModel(
            Speck(number_of_rounds=2),
            "00000000011111001110000000000000",
            "???????????????1???????????????1",
        )
        formulation = model.milp_model()
        builds.append(monotonic() - started)
    assert model is not None and formulation is not None
    results = [GLPKSolver(timeout_seconds=30).solve(formulation) for _ in range(args.repeats)]
    if any(result.status is not MILPStatus.OPTIMAL for result in results):
        raise RuntimeError("GLPK did not solve")
    trails = [model.decode_trail(result.assignment) for result in results]
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "Speck32/64-2 semi-deterministic truncated MILP",
            "timeout_seconds": 30,
        },
        "result": {
            "solver": "GLPKSolver",
            "repeats": args.repeats,
            "variables": len(formulation.variables),
            "constraints": len(formulation.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(result.runtime_seconds for result in results),
            "solver_status": MILPStatus.OPTIMAL.value,
            "assignment_valid": all(len(trail.transitions) == 2 for trail in trails),
            "peak_memory_bytes_median": None,
            "peak_memory_status": "not_reported_by_glpk_driver",
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
