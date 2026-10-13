#!/usr/bin/env python3
"""Benchmark whole-graph SAT trail assembly with canonical SAT solvers."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import (
    CryptoMiniSatSolver,
    KissatSolver,
    MinisatSolver,
    SatStatus,
)
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import (
    WordDifferentialSATModel,
    WordLinearSATModel,
)


def _model(kind):
    if kind == "xor_differential":
        return WordDifferentialSATModel(
            ToySpeck(2),
            fixed_weight=1,
            nonzero_input="plaintext",
            fixed_input_differences={"key": 0},
        )
    return WordLinearSATModel(
        ToySpeck(3),
        maximum_weight=1,
        nonzero_input="plaintext",
        fixed_inputs={"key": 0},
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


def _benchmark(kind, solver_name, repeats):
    construction_times = []
    formula = model = None
    for _ in range(repeats):
        started = monotonic()
        model = _model(kind)
        formula = model.cnf_formula()
        construction_times.append(monotonic() - started)
    assert model is not None and formula is not None
    solver = _solver(solver_name)
    results = [solver.solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{solver_name} did not solve {kind} as satisfiable")
    for result in results:
        if result.assignment is None or not formula.is_satisfied(result.assignment):
            raise RuntimeError(f"{solver_name} returned an invalid {kind} assignment")
        trail = model.decode_characteristic(result.assignment)
        if not model.check_characteristic(trail):
            raise RuntimeError(f"{solver_name} returned an invalid {kind} trail")
    peak_memory = tuple(
        result.peak_memory_bytes for result in results if result.peak_memory_bytes is not None
    )
    return {
        "kind": kind,
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
            "xor_differential": "ToySpeck-2, fixed weight 1, nonzero plaintext, zero key difference",
            "xor_linear": "ToySpeck-3, maximum weight 1, nonzero plaintext, concrete zero key",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(kind, solver, arguments.repeats)
            for kind in ("xor_differential", "xor_linear")
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
