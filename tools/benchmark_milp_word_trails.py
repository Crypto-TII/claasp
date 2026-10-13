#!/usr/bin/env python3
"""Benchmark portable generic differential and linear MILP Word trails."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.primitives import ToySpeck
from claasp.representations.constraints.milp import WordDifferentialMILPModel, WordLinearMILPModel


def _models():
    return {
        "xor_differential": lambda: WordDifferentialMILPModel(
            ToySpeck(2),
            fixed_weight=1,
            fixed_input_differences={"key": 0},
            nonzero_input="plaintext",
        ),
        "xor_linear": lambda: WordLinearMILPModel(
            ToySpeck(3), maximum_weight=1, fixed_inputs={"key": 0}, nonzero_input="plaintext"
        ),
    }


def _benchmark(kind, factory, repeats):
    build_times = []
    model = formulation = None
    for _ in range(repeats):
        started = monotonic()
        model = factory()
        formulation = model.milp_model()
        build_times.append(monotonic() - started)
    assert model is not None and formulation is not None
    results = [GLPKSolver(timeout_seconds=30).solve(formulation) for _ in range(repeats)]
    if any(result.status is not MILPStatus.OPTIMAL for result in results):
        raise RuntimeError(f"GLPK did not solve {kind}")
    trails = [model.decode_characteristic(result.assignment) for result in results]
    return {
        "strategy": kind,
        "solver": "GLPKSolver",
        "repeats": repeats,
        "variables": len(formulation.variables),
        "constraints": len(formulation.constraints),
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": MILPStatus.OPTIMAL.value,
        "assignment_valid": all(model.check_characteristic(trail) for trail in trails),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_glpk_driver",
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
            "description": "portable exact-CNF MILP translation for ToySpeck differential and linear trails",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(kind, factory, arguments.repeats) for kind, factory in _models().items()
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
