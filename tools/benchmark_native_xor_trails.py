#!/usr/bin/env python3
"""Benchmark ordinary and native-XOR complete SAT trail formulas."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CryptoMiniSatSolver, SatStatus
from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import (
    NativeXorCNFFormula,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
    WordLinearSATModel,
)


def _model(kind, native):
    if kind == "xor_differential":
        options = {
            "fixed_weight": 1,
            "nonzero_input": "plaintext",
            "fixed_input_differences": {"key": 0},
        }
        if native:
            return WordDifferentialNativeXorSATModel(ToySpeck(2), **options)
        return WordDifferentialSATModel(ToySpeck(2), **options)
    options = {"maximum_weight": 1, "nonzero_input": "plaintext", "fixed_inputs": {"key": 0}}
    if native:
        return WordLinearNativeXorSATModel(ToySpeck(3), **options)
    return WordLinearSATModel(ToySpeck(3), **options)


def _canonical(clauses):
    return {frozenset(clause) for clause in clauses}


def _benchmark(kind, native, repeats):
    construction_times = []
    formula = model = None
    for _ in range(repeats):
        started = monotonic()
        model = _model(kind, native)
        formula = model.cnf_formula()
        construction_times.append(monotonic() - started)
    assert model is not None and formula is not None
    solver = CryptoMiniSatSolver(timeout_seconds=30)
    results = [solver.solve(formula) for _ in range(repeats)]
    if any(result.status is not SatStatus.SATISFIABLE for result in results):
        raise RuntimeError(f"CryptoMiniSat did not solve {kind} ({native=})")
    for result in results:
        if result.assignment is None or not formula.is_satisfied(result.assignment):
            raise RuntimeError("CryptoMiniSat returned an invalid assignment")
        trail = model.decode_characteristic(result.assignment)
        if not model.check_characteristic(trail):
            raise RuntimeError("CryptoMiniSat returned an invalid trail")
    parity_exact = None
    if isinstance(formula, NativeXorCNFFormula):
        ordinary = _model(kind, False).cnf_formula()
        expanded = formula.expanded_cnf()
        parity_exact = expanded.clause_count == ordinary.clause_count and _canonical(
            expanded.clauses
        ) == _canonical(ordinary.clauses)
    peak_memory = tuple(
        result.peak_memory_bytes for result in results if result.peak_memory_bytes is not None
    )
    return {
        "kind": kind,
        "formulation": "native_xor" if native else "ordinary_cnf",
        "solver": type(solver).__name__,
        "solver_version": solver.version(),
        "repeats": repeats,
        "variables": formula.variable_count,
        "ordinary_clauses": formula.clause_count,
        "native_xor_records": formula.native_xor_count if native else 0,
        "literals": formula.literal_count,
        "construction_seconds_median": median(construction_times),
        "solver_seconds_median": median(result.runtime_seconds for result in results),
        "solver_status": SatStatus.SATISFIABLE.value,
        "assignment_valid": True,
        "trail_valid": True,
        "expanded_cnf_exact": parity_exact,
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
            _benchmark(kind, native, arguments.repeats)
            for kind in ("xor_differential", "xor_linear")
            for native in (False, True)
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
