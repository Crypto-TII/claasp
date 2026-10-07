#!/usr/bin/env python3
"""Benchmark portable and recovered probabilistic-truncated Speck SAT assembly."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver, SatStatus
from claasp.primitives import Speck
from claasp.representations.constraints.sat import (
    SpeckProbabilisticTruncatedSATModel,
    SpeckSemiDeterministicTruncatedSATModel,
)


def _solver(name):
    if name == "minisat":
        return MinisatSolver(timeout_seconds=30)
    if name == "kissat":
        return KissatSolver(timeout_seconds=30)
    return CryptoMiniSatSolver(timeout_seconds=30)


def _solver_version(solver):
    if callable(getattr(solver, "version", None)):
        return solver.version()
    completed = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", "minisat"],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unreported"


def _model(strategy):
    model_type = (
        SpeckProbabilisticTruncatedSATModel
        if strategy == "portable_counter"
        else SpeckSemiDeterministicTruncatedSATModel
    )
    return model_type(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
        maximum_scaled_weight=100,
    )


def _benchmark(strategy, solver_name, repeats):
    construction_times = []
    formula = model = None
    for _ in range(repeats):
        started = monotonic()
        model = _model(strategy)
        formula = model.cnf_formula()
        construction_times.append(monotonic() - started)
    assert model is not None and formula is not None
    solver = _solver(solver_name)
    results = [solver.solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{strategy}/{solver_name} did not solve the shared trail")
    for result in results:
        if result.assignment is None or not formula.is_satisfied(result.assignment):
            raise RuntimeError(f"{strategy}/{solver_name} returned an invalid assignment")
        if model.decode_trail(result.assignment).scaled_weight != 100:
            raise RuntimeError(f"{strategy}/{solver_name} returned an invalid bounded trail")
    peak_memory = tuple(
        result.peak_memory_bytes for result in results if result.peak_memory_bytes is not None
    )
    return {
        "strategy": strategy,
        "solver": type(solver).__name__,
        "solver_version": _solver_version(solver),
        "repeats": repeats,
        "variables": formula.variable_count,
        "clauses": formula.clause_count,
        "literals": formula.literal_count,
        "construction_seconds_median": median(construction_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": True,
        "trail_valid": True,
        "peak_memory_bytes_median": median(peak_memory) if peak_memory else None,
        "peak_memory_status": "measured" if peak_memory else "not_reported",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    payload = {
        "schema_version": 1,
        "workload": {
            "description": "Speck32/64-2 trail with scaled weight at most 100",
            "timeout_seconds": 30,
            "comparison": "same graph, boundaries, objective, solver, settings, and host",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(strategy, solver, arguments.repeats)
            for strategy in ("portable_counter", "recovered_windows")
            for solver in ("minisat", "kissat", "cryptominisat")
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
