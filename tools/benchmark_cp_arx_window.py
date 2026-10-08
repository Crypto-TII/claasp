#!/usr/bin/env python3
"""Compare exact and legacy n-window Speck CP formulations."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import Speck
from claasp.representations.constraints.cp import (
    SpeckARXWindowDifferentialCPModel,
    SpeckDifferentialCPModel,
)
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import PropagationProblem


def _benchmark(name, factory, repeats):
    builds = []
    model = query = None
    for _ in range(repeats):
        started = monotonic()
        model = factory()
        query = model.cp_model()
        builds.append(monotonic() - started)
    assert model is not None and query is not None
    results = [
        MiniZincSolver(solver="chuffed", timeout_seconds=30).solve(query) for _ in range(repeats)
    ]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError(f"Chuffed did not solve {name}")
    trails = [model.decode_trail(result.assignment) for result in results]
    return {
        "strategy": name,
        "solver": "MiniZincSolver/chuffed",
        "repeats": repeats,
        "variables": len(query.declarations),
        "constraints": len(query.constraints),
        "construction_seconds_median": median(builds),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": CPStatus.SATISFIED.value,
        "assignment_valid": all(trail.total_weight <= 45 for trail in trails),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_minizinc_driver",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")

    def problem():
        return PropagationProblem(Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=45)

    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "Speck32/64-3 exact and n-window CP feasibility",
            "timeout_seconds": 30,
        },
        "results": [
            _benchmark("exact", lambda: SpeckDifferentialCPModel(problem()), args.repeats),
            _benchmark(
                "window_3",
                lambda: SpeckARXWindowDifferentialCPModel(problem(), window_sizes=(3, 3, 3)),
                args.repeats,
            ),
        ],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
