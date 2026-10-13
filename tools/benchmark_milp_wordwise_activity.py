#!/usr/bin/env python3
"""Benchmark the recovered wordwise branch-number activity model."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import ToyAES
from claasp.representations.constraints.milp import (
    WordwiseBranchNumberActiveSBoxesMILPModel,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds, solves = [], []
    formulation = None
    for _ in range(args.repeats):
        started = monotonic()
        model = WordwiseBranchNumberActiveSBoxesMILPModel(
            ToyAES(number_of_rounds=4),
            active_input="plaintext",
            zero_difference_inputs=("key",),
        )
        formulation = model.milp_model()
        builds.append(monotonic() - started)
        solved = GLPKSolver(timeout_seconds=30).solve(formulation)
        if solved.status is not MILPStatus.OPTIMAL:
            raise RuntimeError("GLPK did not prove the activity optimum")
        result = model.decode_activity(solved.assignment)
        if result.active_sboxes != 25:
            raise RuntimeError("unexpected ToyAES activity optimum")
        solves.append(solved.runtime_seconds)
    assert formulation is not None
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "four-round ToyAES wordwise active-S-box lower bound",
            "timeout_seconds": 30,
        },
        "result": {
            "solver": "GLPKSolver",
            "repeats": args.repeats,
            "variables": len(formulation.variables),
            "constraints": len(formulation.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(solves),
            "solver_status": MILPStatus.OPTIMAL.value,
            "minimum_active_sboxes": 25,
            "assignment_valid": True,
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
