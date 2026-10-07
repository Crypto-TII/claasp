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

from claasp.primitives import Simon, Speck
from claasp.representations.constraints.sat import (
    BooleanCNFModel,
    BooleanNativeXorModel,
    CryptoMiniSatDimacsExporter,
    NativeXorCNFFormula,
)
from claasp.representations.constraints.sat.exporters import DimacsExporter


def _benchmark(name, primitive, strategy, repeats):
    times = []
    formula = None
    for _ in range(repeats):
        started = monotonic()
        formula = (
            BooleanNativeXorModel(primitive).cnf_formula()
            if strategy == "native_xor"
            else BooleanCNFModel(primitive).cnf_formula()
        )
        times.append(monotonic() - started)
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
    return {
        "primitive": name,
        "strategy": strategy,
        "repeats": repeats,
        "variables": formula.variable_count,
        "ordinary_clauses": formula.clause_count,
        "native_xor_clauses": native_count,
        "expanded_cnf_clauses": expanded_count,
        "export_bytes": len(exported.encode("ascii")),
        "construction_seconds_median": median(times),
        "solver": None,
        "solver_status": "not_run: CryptoMiniSat is not installed in the canonical image",
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
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "results": [
            _benchmark(name, primitive, strategy, arguments.repeats)
            for name, primitive in primitives
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
