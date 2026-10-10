#!/usr/bin/env python3
"""Benchmark independent and legacy-exclusion paired SAT characteristics."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import replace
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, MinisatSolver, SatStatus
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import SharedDifferencePairedWordDifferentialSATModel


def _benchmark(strategy, solver_type, repeats):
    build_times = []
    model = formula = None
    for _ in range(repeats):
        started = monotonic()
        model = SharedDifferencePairedWordDifferentialSATModel(
            ToySpeck(2),
            fixed_total_weight=5,
            fixed_input_differences={"key": 0},
            nonzero_input="plaintext",
        )
        formula = model.cnf_formula()
        if strategy == "shared_input_without_output_exclusion":
            retained = tuple(
                position
                for position, label in enumerate(formula.provenance)
                if label != "paired_modadd_output_exclusion"
            )
            formula = replace(
                formula,
                clauses=tuple(formula.clauses[position] for position in retained),
                provenance=tuple(formula.provenance[position] for position in retained),
            )
        build_times.append(monotonic() - started)
    assert formula is not None
    results = [solver_type(timeout_seconds=30).solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{strategy}/{solver_type.__name__} did not solve")
    return {
        "strategy": strategy,
        "solver": solver_type.__name__,
        "repeats": repeats,
        "variables": formula.variable_count,
        "clauses": formula.clause_count,
        "literals": formula.literal_count,
        "construction_seconds_median": median(build_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": all(
            result.assignment is not None and formula.is_satisfied(result.assignment)
            for result in results
        ),
        "peak_memory_bytes_median": None,
        "peak_memory_status": "not_reported_by_sat_drivers",
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
            "description": "ToySpeck-2 paired characteristics at fixed total weight 5",
            "comparison": "same shared input, weight, solvers, settings, and host",
            "timeout_seconds": 30,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(strategy, solver_type, arguments.repeats)
            for strategy in (
                "shared_input_without_output_exclusion",
                "legacy_modadd_output_exclusion",
            )
            for solver_type in (MinisatSolver, KissatSolver, CryptoMiniSatSolver)
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
