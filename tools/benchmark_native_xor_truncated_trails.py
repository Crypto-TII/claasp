#!/usr/bin/env python3
"""Benchmark ordinary and native-XOR deterministic-truncated SAT trails."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, SatStatus
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import (
    WordDeterministicTruncatedNativeXorSATModel,
    WordDeterministicTruncatedSATModel,
)


def _version():
    completed = subprocess.run(
        ["cryptominisat5", "--version"], text=True, capture_output=True, check=False
    )
    text = completed.stdout or completed.stderr
    return text.splitlines()[0] if text else "unreported"


def _benchmark(strategy, repeats):
    model_type = (
        WordDeterministicTruncatedSATModel
        if strategy == "ordinary_cnf"
        else WordDeterministicTruncatedNativeXorSATModel
    )
    options = {
        "fixed_input_patterns": {"plaintext": "00000001", "key": "0" * 16},
        "output_pattern": "???0????",
    }
    build_times = []
    model = formula = None
    for _ in range(repeats):
        started = monotonic()
        model = model_type(ToySpeck(2), **options)
        formula = model.cnf_formula()
        build_times.append(monotonic() - started)
    assert model is not None and formula is not None
    results = [CryptoMiniSatSolver(timeout_seconds=30).solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{strategy} did not solve")
    if any(result.assignment is None for result in results):
        raise RuntimeError("solver returned no satisfying assignment")
    assignments = [result.assignment for result in results if result.assignment is not None]
    trails = [model.decode_characteristic(assignment) for assignment in assignments]
    return {
        "strategy": strategy,
        "solver": "CryptoMiniSatSolver",
        "solver_version": _version(),
        "repeats": repeats,
        "variables": formula.variable_count,
        "cnf_clauses": formula.clause_count,
        "native_xor_records": getattr(formula, "native_xor_count", 0),
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": all(formula.is_satisfied(assignment) for assignment in assignments),
        "trail_valid": all(str(trail.output_pattern) == "???0????" for trail in trails),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_cryptominisat_driver",
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
            "description": "fixed ToySpeck-2 deterministic-truncated propagation",
            "comparison": "same relation, boundaries, solver, settings, and host",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(strategy, arguments.repeats)
            for strategy in ("ordinary_cnf", "native_xor")
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
