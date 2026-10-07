#!/usr/bin/env python3
"""Benchmark deterministic-truncated ToySpeck SMT assembly under Z3."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.smt import WordDeterministicTruncatedSMTModel


def _model():
    return WordDeterministicTruncatedSMTModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    build_times = []
    model = formula = None
    for _ in range(arguments.repeats):
        started = monotonic()
        model = _model()
        formula = model.smt_formula()
        build_times.append(monotonic() - started)
    assert model is not None and formula is not None
    solver = Z3Solver(timeout_seconds=30)
    results = [solver.solve(formula) for _ in range(arguments.repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError("Z3 did not solve the deterministic-truncated fixture")
    for result in results:
        if result.assignment is None or not model.check_characteristic(
            model.decode_characteristic(result.assignment)
        ):
            raise RuntimeError("Z3 returned an invalid deterministic-truncated trail")
    payload = {
        "schema_version": 1,
        "workload": {
            "description": "fixed ToySpeck-2 deterministic-truncated trail",
            "timeout_seconds": 30,
            "sat_comparison": "docs/architecture/audits/data/sat_truncated_trail_benchmark.json",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "result": {
            "solver": "Z3Solver",
            "solver_version": solver.version(),
            "repeats": arguments.repeats,
            "variables": len(formula.variables),
            "assertions": formula.assertion_count,
            "construction_seconds_median": median(build_times),
            "solver_seconds_median": median(result.runtime_seconds for result in results),
            "solver_status": SatStatus.SATISFIABLE.value,
            "assignment_valid": True,
            "trail_valid": True,
            "peak_memory_bytes_median": None,
            "peak_memory_status": "not_reported_by_z3_driver",
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
