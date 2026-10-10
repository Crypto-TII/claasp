"""Cross-backend execution of newly covered functional word components."""

import pytest

from claasp import ArrayType, Primitive
from claasp.components import BitwiseNot, BitwiseOr, ModularSubtract, Shift
from claasp.domains import Word
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

pytestmark = pytest.mark.external


def _primitive():
    array_type = ArrayType(Word(8), (1,))
    primitive = Primitive("or_not_shift", {name: array_type for name in ("a", "b", "c")})
    primitive._builder.add_round()
    merged = primitive._builder.add_component(
        BitwiseOr(
            (primitive.graph.input("a"), primitive.graph.input("b"), primitive.graph.input("c"))
        )
    )
    complemented = primitive._builder.add_component(BitwiseNot(merged))
    left = primitive._builder.add_component(Shift(complemented, 3, "left"))
    right = primitive._builder.add_component(Shift(left, 2, "right"))
    primitive._builder.set_output(
        primitive._builder.add_component(
            ModularSubtract((right, primitive.graph.input("a"), primitive.graph.input("b")))
        )
    )
    return primitive


def test_all_portable_solver_backends_execute_or_not_and_shift():
    primitive = _primitive()
    cnf = BooleanCNFModel(primitive).cnf_formula()

    minisat = MinisatSolver(timeout_seconds=30).solve(cnf)
    assert minisat.status is SatStatus.SATISFIABLE
    assert cnf.is_satisfied(minisat.assignment)

    smt = BooleanSMTModel(primitive).smt_formula()
    z3 = Z3Solver(timeout_seconds=30).solve(smt)
    assert z3.status is SatStatus.SATISFIABLE
    assert cnf.is_satisfied(z3.assignment)

    cp = BooleanMiniZincLowerer().lower(cnf)
    chuffed = MiniZincSolver("chuffed", timeout_seconds=30).solve(cp)
    assert chuffed.status is CPStatus.SATISFIED
    assert cnf.is_satisfied(chuffed.assignment)

    milp = BooleanGraphMILPModel(primitive).milp_model()
    glpk = GLPKSolver(timeout_seconds=30).solve(milp)
    assert glpk.is_feasible
    assert milp.is_feasible(glpk.assignment)
