#!/usr/bin/env python3
"""Benchmark complete modular-add and S-box boomerang compositions."""

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp import ArrayType, PrimitiveBuilder
from claasp.components import ModularAdd
from claasp.domains import Word
from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import Present, Speck
from claasp.representations.constraints.cp import (
    ModularAddBoomerangCPModel,
    ModularAddBoomerangTrailCPModel,
    PresentDifferentialCPModel,
    SBoxBoomerangCPModel,
    SBoxBoomerangTrailCPModel,
    SpeckBoomerangCPModel,
    WordDifferentialCPModel,
)
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import PropagationProblem


def _version():
    completed = subprocess.run(
        ["minizinc", "--version"], text=True, capture_output=True, check=False
    )
    return completed.stdout.splitlines()[0] if completed.returncode == 0 else "unreported"


def _graph(name):
    builder = PrimitiveBuilder(
        name,
        {"left": ArrayType(Word(4), (1,)), "right": ArrayType(Word(4), (1,))},
    )
    builder.add_round()
    output = builder.add_component(ModularAdd((builder.input("left"), builder.input("right"))))
    return builder.build(output)


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


def _sbox_model():
    upper = PresentDifferentialCPModel(
        PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8)
    )
    lower = PresentDifferentialCPModel(
        PropagationProblem(Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8)
    )
    component = next(
        item for item in upper.primitive.graph.components if item.component_id == "sbox_1_0"
    )
    return SBoxBoomerangTrailCPModel(upper, lower, SBoxBoomerangCPModel(component), nibble=0)


def _speck_model():
    return SpeckBoomerangCPModel(
        Speck(number_of_rounds=3),
        switch_round=1,
        upper_maximum_weight=20,
        lower_maximum_weight=20,
    )


def _benchmark(model_factory, repeats, solver):
    builds = []
    model = query = None
    for _ in range(repeats):
        started = monotonic()
        model = model_factory()
        query = model.cp_model()
        builds.append(monotonic() - started)
    results = [solver.solve(query) for _ in range(repeats)]
    if any(result.status is not CPStatus.SATISFIED for result in results):
        raise RuntimeError("Chuffed did not solve the boomerang composition")
    trails = [model.decode_trail(result.assignment) for result in results]
    return {
        "solver": "MiniZincSolver(chuffed)",
        "solver_version": _version(),
        "repeats": repeats,
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
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    solver = MiniZincSolver("chuffed", timeout_seconds=30)
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workloads": (
            {
                "name": "modular_add",
                "description": "two exact four-bit modular-add trails joined by an exact switch",
                "timeout_seconds": 30,
                "result": _benchmark(_model, args.repeats, solver),
            },
            {
                "name": "sbox",
                "description": "two exact PRESENT-2 trails joined at one exact S-box BCT switch",
                "timeout_seconds": 30,
                "result": _benchmark(_sbox_model, args.repeats, solver),
            },
            {
                "name": "speck_automatic_partition",
                "description": "Speck-3 automatically partitioned around its round-1 add",
                "timeout_seconds": 30,
                "result": _benchmark(_speck_model, args.repeats, solver),
            },
        ),
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
