#!/usr/bin/env python3
"""Compare portable and legacy-window probabilistic truncated SAT addition."""

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
from claasp.representations.constraints.sat import (
    ModularAddSemiDeterministicTruncatedSATModel,
    ProbabilisticTruncatedModularAddSATModel,
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
        ProbabilisticTruncatedModularAddSATModel
        if strategy == "counter_based"
        else ModularAddSemiDeterministicTruncatedSATModel
    )
    return model_type(
        16,
        left_pattern="0" * 15 + "1",
        right_pattern="0" * 16,
        output_pattern="0" * 15 + "1",
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
        raise RuntimeError(f"{solver_name} did not solve {strategy}")
    for result in results:
        if result.assignment is None or not formula.is_satisfied(result.assignment):
            raise RuntimeError(f"{solver_name} returned an invalid assignment")
        transition = model.decode_transition(result.assignment)
        scaled_weight = transition.scaled_weight if strategy == "counter_based" else transition[3]
        if scaled_weight != 100:
            raise RuntimeError(f"{solver_name} returned the wrong {strategy} weight")
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
        "transition_valid": True,
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
            "description": "16-bit modular addition 0001 + 0000 -> 0001 at scaled weight 100",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(strategy, solver, arguments.repeats)
            for strategy in ("counter_based", "legacy_window")
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
