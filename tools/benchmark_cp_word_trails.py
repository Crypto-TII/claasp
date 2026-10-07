#!/usr/bin/env python3
"""Benchmark portable generic differential and linear MiniZinc trails."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.cp import WordDifferentialCPModel, WordLinearCPModel


def _models():
    return {
        "xor_differential": lambda: WordDifferentialCPModel(
            ToySpeck(2),
            fixed_weight=1,
            fixed_input_differences={"key": 0},
            nonzero_input="plaintext",
        ),
        "xor_linear": lambda: WordLinearCPModel(
            ToySpeck(3),
            maximum_weight=1,
            fixed_inputs={"key": 0},
            nonzero_input="plaintext",
        ),
    }


def _version():
    completed = subprocess.run(
        ["minizinc", "--version"], text=True, capture_output=True, check=False
    )
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def _benchmark(kind, factory, repeats):
    build_times = []
    model = query = None
    for _ in range(repeats):
        started = monotonic()
        model = factory()
        query = model.cp_model()
        build_times.append(monotonic() - started)
    assert model is not None and query is not None
    solver = MiniZincSolver(solver="chuffed", timeout_seconds=30)
    results = [solver.solve(query) for _ in range(repeats)]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError(f"Chuffed did not solve {kind}")
    trails = [model.decode_characteristic(result.assignment) for result in results]
    return {
        "strategy": kind,
        "solver": "MiniZincSolver/chuffed",
        "repeats": repeats,
        "variables": len(query.declarations),
        "constraints": len(query.constraints),
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": CPStatus.SATISFIED.value,
        "assignment_valid": all(model.check_characteristic(trail) for trail in trails),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_minizinc_driver",
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
            "description": "portable exact-CNF MiniZinc translation for ToySpeck differential and linear trails",
            "timeout_seconds": 30,
        },
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "minizinc": _version(),
        },
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
