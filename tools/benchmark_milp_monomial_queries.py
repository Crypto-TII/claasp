#!/usr/bin/env python3
"""Benchmark portable Simon monomial degree and cube queries."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import Simon
from claasp.representations.constraints.milp import (
    CubeMonomialFeasibilityMILPModel,
    CubeSuperpolyQuery,
    MonomialDegreeMILPModel,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds, solves = [], []
    degree = None
    for _ in range(args.repeats):
        started = monotonic()
        query = MonomialDegreeMILPModel(
            Simon(number_of_rounds=1), output_bit=0, variable_input="plaintext"
        )
        degree = query.milp_model()
        builds.append(monotonic() - started)
        solved = GLPKSolver(timeout_seconds=30).solve(degree)
        if (
            solved.status is not MILPStatus.OPTIMAL
            or query.decode_bound(solved.assignment).degree != 2
        ):
            raise RuntimeError("unexpected Simon degree result")
        solves.append(solved.runtime_seconds)
    feasible = CubeMonomialFeasibilityMILPModel(
        Simon(number_of_rounds=1),
        output_bit=0,
        variable_input="plaintext",
        cube_positions=(1, 8),
    )
    cube_status = GLPKSolver(timeout_seconds=30).solve(feasible.milp_model()).status
    superpoly_times = []
    superpoly = None
    for _ in range(args.repeats):
        started = monotonic()
        superpoly = CubeSuperpolyQuery(
            Simon(number_of_rounds=1),
            output_bit=0,
            cube_input="plaintext",
            cube_positions=(1, 8),
            symbolic_input="key",
            symbolic_positions=(0, 1, 2, 3),
        ).compute()
        superpoly_times.append(monotonic() - started)
    if superpoly.anf_terms != ((),):
        raise RuntimeError("unexpected exact Simon cube superpoly")
    assert degree is not None
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {"description": "one-round Simon output-bit-zero monomial queries"},
        "result": {
            "solver": "GLPKSolver",
            "repeats": args.repeats,
            "variables": len(degree.variables),
            "constraints": len(degree.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(solves),
            "degree_bound": 2,
            "cube_1_8_feasible": cube_status is MILPStatus.OPTIMAL,
            "cube_1_8_key_0_3_superpoly_anf_terms": [list(term) for term in superpoly.anf_terms],
            "exact_superpoly_seconds_median": median(superpoly_times),
            "solver_status": MILPStatus.OPTIMAL.value,
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
