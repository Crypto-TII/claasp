#!/usr/bin/env python3
"""Benchmark OR, NOT, and SHIFT functional graph lowering across backends."""

import argparse
import json
import platform
import sys
from pathlib import Path
from statistics import median

from claasp import Primitive, ValueType, Word
from claasp.components import BitwiseNot, BitwiseOr, ModularSubtract, Shift
from claasp.drivers.solvers import (
    CPStatus,
    GLPKSolver,
    MinisatSolver,
    MiniZincSolver,
    SatStatus,
    Z3Solver,
)
from claasp.representations.constraints.cp import BooleanMiniZincLowerer
from claasp.representations.constraints.milp import BooleanGraphMILPModel
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.constraints.smt import BooleanSMTModel


def _primitive():
    value_type = ValueType(Word(8), (1,))
    primitive = Primitive("or_not_shift", {name: value_type for name in ("a", "b", "c")})
    primitive.add_round()
    merged = primitive.add_component(
        BitwiseOr((primitive.input("a"), primitive.input("b"), primitive.input("c")))
    )
    complemented = primitive.add_component(BitwiseNot(merged))
    left = primitive.add_component(Shift(complemented, 3, "left"))
    right = primitive.add_component(Shift(left, 2, "right"))
    primitive.set_output(
        primitive.add_component(
            ModularSubtract((right, primitive.input("a"), primitive.input("b")))
        )
    )
    return primitive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    primitive = _primitive()
    cnf = BooleanCNFModel(primitive).cnf_formula()
    workloads = (
        ("SAT", MinisatSolver(timeout_seconds=30), cnf, SatStatus.SATISFIABLE),
        (
            "SMT",
            Z3Solver(timeout_seconds=30),
            BooleanSMTModel(primitive).smt_formula(),
            SatStatus.SATISFIABLE,
        ),
        (
            "CP",
            MiniZincSolver("chuffed", timeout_seconds=30),
            BooleanMiniZincLowerer().lower(cnf),
            CPStatus.SATISFIED,
        ),
        (
            "MILP",
            GLPKSolver(timeout_seconds=30),
            BooleanGraphMILPModel(primitive).milp_model(),
            None,
        ),
    )
    rows = []
    for backend, solver, formulation, expected in workloads:
        results = [solver.solve(formulation) for _ in range(args.repeats)]
        valid = all(
            (result.is_feasible and formulation.is_feasible(result.assignment))
            if backend == "MILP"
            else result.status is expected and cnf.is_satisfied(result.assignment)
            for result in results
        )
        if not valid:
            raise RuntimeError(f"{backend} failed the functional component workload")
        rows.append(
            {
                "backend": backend,
                "solver": type(solver).__name__,
                "repeats": args.repeats,
                "solver_seconds_median": median(result.runtime_seconds for result in results),
                "assignment_valid": True,
            }
        )
    payload = {
        "schema_version": 1,
        "environment": {"platform": platform.platform(), "python": sys.version.split()[0]},
        "workload": {
            "description": "8-bit OR, NOT, fixed shifts, and three-input modular-subtract graph",
            "variables": len(cnf.variables),
            "clauses": len(cnf.clauses),
        },
        "results": rows,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
