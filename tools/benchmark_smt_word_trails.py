#!/usr/bin/env python3
"""Benchmark exact ToySpeck differential and linear SMT trails under Z3."""

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
from claasp.representations.constraints.smt import WordDifferentialSMTModel, WordLinearSMTModel


def _models():
    primitive = ToySpeck(2)
    return {
        "xor_differential": lambda: WordDifferentialSMTModel(
            primitive, fixed_weight=1, fixed_input_differences={"key": 0}
        ),
        "xor_linear": lambda: WordLinearSMTModel(
            primitive, maximum_weight=2, nonzero_input="plaintext", fixed_inputs={"key": 0}
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    solver = Z3Solver(timeout_seconds=30)
    rows = []
    for semantics, factory in _models().items():
        build_times = []
        model = formula = None
        for _ in range(arguments.repeats):
            started = monotonic()
            model = factory()
            formula = model.smt_formula()
            build_times.append(monotonic() - started)
        assert model is not None and formula is not None
        results = [solver.solve(formula) for _ in range(arguments.repeats)]
        if any(result.status is not SatStatus.SATISFIABLE for result in results):
            raise RuntimeError(f"Z3 did not solve the {semantics} fixture")
        for result in results:
            trail = model.decode_characteristic(result.assignment)
            if not model.check_characteristic(trail):
                raise RuntimeError(f"Z3 returned an invalid {semantics} trail")
        rows.append(
            {
                "semantics": semantics,
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
            }
        )
    payload = {
        "schema_version": 1,
        "workload": {
            "description": "fixed-weight differential and bounded-weight linear ToySpeck-2 trails",
            "timeout_seconds": 30,
            "sat_comparison": "docs/architecture/audits/data/sat_trail_assembly_benchmark.json",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": rows,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
