#!/usr/bin/env python3
"""Benchmark the one-hot and Espresso AES S-box MILP strategies with GLPK."""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from statistics import median
from time import monotonic

from claasp.composites.aes import AES_SBOX
from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.representations.constraints.milp import (
    LPExporter,
    SBoxMILPInequalityStrategy,
    SBoxTransitionMILPModel,
    SBoxXorDifferentialEspressoMILPModel,
    SBoxXorLinearEspressoMILPModel,
    load_bundled_sbox_milp_inequalities,
)
from claasp.semantics.cryptanalysis import TrailKind

MEMORY = re.compile(r"Memory used:\s+[0-9.]+ Mb \(([0-9]+) bytes\)")


def _factories(kind: TrailKind):
    yield "one_hot", lambda: SBoxTransitionMILPModel(AES_SBOX, kind)
    model_type = (
        SBoxXorDifferentialEspressoMILPModel
        if kind is TrailKind.XOR_DIFFERENTIAL
        else SBoxXorLinearEspressoMILPModel
    )
    yield (
        "espresso",
        lambda: model_type(
            load_bundled_sbox_milp_inequalities("aes", kind, SBoxMILPInequalityStrategy.ESPRESSO)
        ),
    )


def _benchmark(kind: TrailKind, strategy: str, factory, repeats: int) -> dict[str, object]:
    construction_times = []
    solve_times = []
    wall_times = []
    memory_bytes = []
    relation = model = result = None
    for _ in range(repeats):
        started = monotonic()
        relation = factory()
        model = relation.milp_model(input_pattern=1)
        construction_times.append(monotonic() - started)
        started = monotonic()
        result = GLPKSolver(timeout_seconds=120).solve(model)
        wall_times.append(monotonic() - started)
        solve_times.append(result.runtime_seconds)
        matched = MEMORY.search(result.stdout)
        if matched:
            memory_bytes.append(int(matched.group(1)))
    assert relation is not None and model is not None and result is not None
    if result.status is not MILPStatus.OPTIMAL or result.assignment is None:
        raise RuntimeError(f"{kind.value}/{strategy} did not return an optimal witness")
    transition = relation.decode_transition(result.assignment)
    if not relation.semantics.check(transition):
        raise RuntimeError(f"{kind.value}/{strategy} returned an invalid transition")
    return {
        "kind": kind.value,
        "strategy": strategy,
        "repeats": repeats,
        "variables": len(model.variables),
        "constraints": len(model.constraints),
        "lp_bytes": len(LPExporter().export(model).encode("ascii")),
        "construction_seconds_first": construction_times[0],
        "construction_seconds_median": median(construction_times),
        "solver_seconds_median": median(solve_times),
        "wall_seconds_median": median(wall_times),
        "solver_memory_bytes_max": max(memory_bytes) if memory_bytes else None,
        "objective": result.objective_value,
        "transition": {
            "input": transition.input_pattern.value,
            "output": transition.output_pattern.value,
            "numerator": transition.numerator,
            "denominator": transition.denominator,
            "sign": transition.sign,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.repeats <= 0:
        parser.error("--repeats must be positive")
    version = subprocess.run(
        ["glpsol", "--version"], text=True, capture_output=True, check=True
    ).stdout.splitlines()[0]
    payload = {
        "schema_version": 1,
        "workload": {
            "sbox": "AES",
            "input_pattern": 1,
            "output_pattern": "optimized",
            "objective": "minimum XOR trail weight",
        },
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "solver": version,
        },
        "results": [
            _benchmark(kind, strategy, factory, arguments.repeats)
            for kind in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR)
            for strategy, factory in _factories(kind)
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
