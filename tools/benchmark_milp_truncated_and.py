#!/usr/bin/env python3
"""Benchmark portable and recovered deterministic-truncated AND MILP models."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.representations.constraints.milp import (
    BitwiseAndDeterministicTruncatedMILPModel,
    BitwiseAndDeterministicTruncatedOneHotMILPModel,
)


def _version():
    completed = subprocess.run(["glpsol", "--version"], text=True, capture_output=True, check=False)
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def _benchmark(strategy, repeats):
    model_type = (
        BitwiseAndDeterministicTruncatedOneHotMILPModel
        if strategy == "portable_one_hot"
        else BitwiseAndDeterministicTruncatedMILPModel
    )
    left = "01?" * 10 + "01"
    right = "001" * 10 + "00"
    output = "".join("0" if a == b == "0" else "?" for a, b in zip(left, right))
    build_times = []
    model = formulation = None
    for _ in range(repeats):
        started = monotonic()
        model = model_type(32)
        formulation = model.milp_model(
            left_pattern=left, right_pattern=right, output_pattern=output
        )
        build_times.append(monotonic() - started)
    assert model is not None and formulation is not None
    solver = GLPKSolver(timeout_seconds=30)
    results = [solver.solve(formulation) for _ in range(repeats)]
    if any(result.status is not MILPStatus.OPTIMAL for result in results):
        raise RuntimeError(f"{strategy} did not optimize")
    for result in results:
        if result.assignment is None or not formulation.is_feasible(result.assignment):
            raise RuntimeError(f"{strategy} returned an invalid assignment")
        model.decode_transition(result.assignment)
    return {
        "strategy": strategy,
        "solver": "GLPKSolver",
        "solver_version": _version(),
        "repeats": repeats,
        "variables": len(formulation.variables),
        "constraints": len(formulation.constraints),
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": MILPStatus.OPTIMAL.value,
        "assignment_valid": True,
        "transition_valid": True,
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
            "description": "fixed 32-bit conservative deterministic-truncated AND",
            "timeout_seconds": 30,
            "comparison": "same relation, patterns, solver, settings, and host",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(strategy, arguments.repeats)
            for strategy in ("portable_one_hot", "recovered_indicator")
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
