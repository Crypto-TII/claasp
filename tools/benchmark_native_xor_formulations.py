#!/usr/bin/env python3
"""Compare ordinary-CNF and native-XOR functional formulations."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, KissatSolver, SatStatus
from claasp.primitives import Simon, Speck
from claasp.representations.constraints.sat import (
    BooleanCNFModel,
    BooleanNativeXorModel,
    CryptoMiniSatDimacsExporter,
    NativeXorCNFFormula,
)
from claasp.representations.constraints.sat.exporters import DimacsExporter


def _benchmark(name, primitive, strategy, solver_name, repeats):
    construction_times = []
    formula = None
    for _ in range(repeats):
        started = monotonic()
        formula = (
            BooleanNativeXorModel(primitive).cnf_formula()
            if strategy == "native_xor"
            else BooleanCNFModel(primitive).cnf_formula()
        )
        construction_times.append(monotonic() - started)
    assert formula is not None
    if strategy == "native_xor":
        if not isinstance(formula, NativeXorCNFFormula):
            raise RuntimeError("native-XOR benchmark produced ordinary CNF")
        exported = CryptoMiniSatDimacsExporter().export(formula, include_variable_map=False)
        native_count = formula.native_xor_count
        expanded_count = formula.expanded_cnf().clause_count
    else:
        exported = DimacsExporter().export(formula, include_variable_map=False)
        native_count = 0
        expanded_count = formula.clause_count
    assumptions = {
        variable: 0
        for variable in formula.variables
        if any(variable.startswith(f"{name}_") for name in primitive.graph.input_ports)
    }
    solver = (
        CryptoMiniSatSolver(timeout_seconds=60)
        if solver_name == "cryptominisat"
        else KissatSolver(timeout_seconds=60)
    )
    results = [solver.solve(formula, assumptions) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"{solver.__class__.__name__} did not solve {name} as satisfiable")
    if any(
        result.assignment is None or not formula.is_satisfied(result.assignment)
        for result in results
    ):
        raise RuntimeError(f"{solver.__class__.__name__} returned an invalid assignment")
    peak_memory = tuple(
        result.peak_memory_bytes for result in results if result.peak_memory_bytes is not None
    )
    return {
        "primitive": name,
        "strategy": strategy,
        "repeats": repeats,
        "variables": formula.variable_count,
        "ordinary_clauses": formula.clause_count,
        "native_xor_clauses": native_count,
        "expanded_cnf_clauses": expanded_count,
        "export_bytes": len(exported.encode("ascii")),
        "construction_seconds_median": median(construction_times),
        "solver": solver.__class__.__name__,
        "solver_version": solver.version(),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": True,
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
    primitives = (
        ("Speck-1", Speck(number_of_rounds=1)),
        ("Simon-1", Simon(number_of_rounds=1)),
    )
    payload = {
        "schema_version": 2,
        "workload": {
            "primitives": ["Speck-1", "Simon-1"],
            "input_assignment": "all-zero",
            "objective": "satisfiability",
            "timeout_seconds": 60,
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(name, primitive, strategy, solver, arguments.repeats)
            for name, primitive in primitives
            for strategy, solver in (
                ("ordinary_cnf", "kissat"),
                ("ordinary_cnf", "cryptominisat"),
                ("native_xor", "cryptominisat"),
            )
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
