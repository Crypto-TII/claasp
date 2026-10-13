#!/usr/bin/env python3
"""Benchmark portable and recovered bitwise-AND MILP formulations."""

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
    BitwiseAndOneHotMILPModel,
    BitwiseAndXorDifferentialMILPModel,
    BitwiseAndXorLinearMILPModel,
)
from claasp.semantics.cryptanalysis import TrailKind


def _version():
    completed = subprocess.run(["glpsol", "--version"], text=True, capture_output=True, check=False)
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def _model(kind, strategy):
    if strategy == "portable_one_hot":
        return BitwiseAndOneHotMILPModel(32, kind)
    return (
        BitwiseAndXorDifferentialMILPModel(32)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else BitwiseAndXorLinearMILPModel(32)
    )


def _patterns(kind):
    left = 0x13579BDF
    right = 0x2468ACE0
    return (
        (left, right, 0x02448AC0)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else (left, right, left | right)
    )


def _benchmark(kind, strategy, repeats):
    build_times = []
    model = formulation = None
    left, right, output = _patterns(kind)
    for _ in range(repeats):
        started = monotonic()
        model = _model(kind, strategy)
        formulation = model.milp_model(
            left_pattern=left, right_pattern=right, output_pattern=output
        )
        build_times.append(monotonic() - started)
    assert model is not None and formulation is not None
    solver = GLPKSolver(timeout_seconds=30)
    results = [solver.solve(formulation) for _ in range(repeats)]
    if any(result.status is not MILPStatus.OPTIMAL for result in results):
        raise RuntimeError(f"{kind.value}/{strategy} did not optimize")
    for result in results:
        if result.assignment is None or not formulation.is_feasible(result.assignment):
            raise RuntimeError(f"{kind.value}/{strategy} returned an invalid assignment")
        if not model.decode_transition(result.assignment).is_possible:
            raise RuntimeError(f"{kind.value}/{strategy} returned an invalid transition")
    return {
        "kind": kind.value,
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
            "description": "fixed supported 32-bit two-input AND transition",
            "timeout_seconds": 30,
            "comparison": "same relation, masks, objective, solver, settings, and host",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(kind, strategy, arguments.repeats)
            for kind in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR)
            for strategy in ("portable_one_hot", "recovered_reduced")
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
