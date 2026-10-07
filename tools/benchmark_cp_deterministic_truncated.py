#!/usr/bin/env python3
"""Benchmark deterministic-truncated ToySpeck CP assembly under Chuffed."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import ToySpeck
from claasp.representations.constraints.cp import WordDeterministicTruncatedCPModel


def _model():
    return WordDeterministicTruncatedCPModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )


def _version():
    completed = subprocess.run(
        ["minizinc", "--version"], text=True, capture_output=True, check=False
    )
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    build_times = []
    model = query = None
    for _ in range(arguments.repeats):
        started = monotonic()
        model = _model()
        query = model.cp_model()
        build_times.append(monotonic() - started)
    assert model is not None and query is not None
    solver = MiniZincSolver(solver="chuffed", timeout_seconds=30)
    results = [solver.solve(query) for _ in range(arguments.repeats)]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError("Chuffed did not solve the deterministic-truncated fixture")
    for result in results:
        if result.assignment is None or not model.check_characteristic(
            model.decode_characteristic(result.assignment)
        ):
            raise RuntimeError("Chuffed returned an invalid deterministic-truncated trail")
    payload = {
        "schema_version": 1,
        "workload": {
            "description": "fixed ToySpeck-2 deterministic-truncated trail",
            "timeout_seconds": 30,
            "sat_comparison": "docs/architecture/audits/data/sat_truncated_trail_benchmark.json",
        },
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "result": {
            "solver": "MiniZincSolver/chuffed",
            "solver_version": _version(),
            "repeats": arguments.repeats,
            "variables": len(query.declarations),
            "constraints": len(query.constraints),
            "construction_seconds_median": median(build_times),
            "solver_seconds_median": median(result.runtime_seconds for result in results),
            "solver_status": CPStatus.SATISFIED.value,
            "assignment_valid": True,
            "trail_valid": True,
            "peak_memory_bytes_median": None,
            "peak_memory_status": "not_reported_by_minizinc_driver",
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
