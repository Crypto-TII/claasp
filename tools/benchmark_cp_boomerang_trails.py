#!/usr/bin/env python3
"""Benchmark complete modular-add boomerang trail composition under Chuffed."""

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp import Primitive, ValueType, Word
from claasp.components import ModularAdd
from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.representations.constraints.cp import (
    ModularAddBoomerangCPModel,
    ModularAddBoomerangTrailCPModel,
    WordDifferentialCPModel,
)


def _version():
    completed = subprocess.run(
        ["minizinc", "--version"], text=True, capture_output=True, check=False
    )
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def _graph(name):
    primitive = Primitive(
        name,
        {"left": ValueType(Word(4), (1,)), "right": ValueType(Word(4), (1,))},
    )
    primitive.add_round()
    primitive.set_output(
        primitive.add_component(ModularAdd((primitive.input("left"), primitive.input("right"))))
    )
    return primitive


def _model():
    options = {
        "maximum_weight": 3,
        "nonzero_input": "left",
        "fixed_input_differences": {"right": 0},
    }
    return ModularAddBoomerangTrailCPModel(
        WordDifferentialCPModel(_graph("upper"), **options),
        WordDifferentialCPModel(_graph("lower"), **options),
        ModularAddBoomerangCPModel(4),
        lower_input="left",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    builds = []
    model = query = None
    for _ in range(args.repeats):
        started = monotonic()
        model = _model()
        query = model.cp_model()
        builds.append(monotonic() - started)
    solver = MiniZincSolver("chuffed", timeout_seconds=30)
    results = [solver.solve(query) for _ in range(args.repeats)]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError("Chuffed did not solve the boomerang composition")
    trails = [model.decode_trail(result.assignment) for result in results]
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "two exact four-bit modular-add trails joined by an exact switch",
            "timeout_seconds": 30,
        },
        "result": {
            "solver": "MiniZincSolver(chuffed)",
            "solver_version": _version(),
            "repeats": args.repeats,
            "declarations": len(query.declarations),
            "constraints": len(query.constraints),
            "construction_seconds_median": median(builds),
            "solver_seconds_median": median(result.runtime_seconds for result in results),
            "solver_status": CPStatus.SATISFIED.value,
            "trails_valid": all(trail.total_weight >= trail.search_weight for trail in trails),
            "search_weight": trails[0].search_weight,
            "exact_decoded_weight": trails[0].total_weight,
            "peak_memory_bytes_median": None,
            "peak_memory_status": "not_reported_by_minizinc_driver",
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
