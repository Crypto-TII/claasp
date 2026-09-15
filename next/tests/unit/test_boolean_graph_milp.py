"""Exact clause inequalities and graph execution witnesses without solvers."""

from itertools import product

import pytest

from claasp_next.primitives import Simon, Speck
from claasp_next.representations.constraints.sat import CNFFormula
from claasp_next.representations.constraints.milp import BooleanGraphMILPModel, cnf_to_milp
from claasp_next.representations.execution import ScalarEvaluator
from claasp_next.drivers.solvers import GLPKSolver, MILPResult, MILPStatus
from claasp_next.representations.constraints.milp import MILPModel


@pytest.mark.parametrize("clause", [(1,), (-1,), (1, 2), (-1, -2), (1, -2), (1, -1), (1, 1, -2)])
def test_binary_inequalities_match_every_clause_assignment(clause):
    formula = CNFFormula(("x", "y"), (clause,), ("test",))
    model = cnf_to_milp(formula)
    for values in product((0, 1), repeat=2):
        assignment = dict(zip(formula.variables, values))
        assert model.is_feasible(assignment) is formula.is_satisfied(assignment)


@pytest.mark.parametrize("primitive", [Speck(number_of_rounds=22), Simon(number_of_rounds=3)])
def test_full_graph_milp_witness_preserves_nonlinear_operations(primitive):
    model = BooleanGraphMILPModel(primitive)
    evaluation = ScalarEvaluator().evaluate(primitive, {"plaintext": (0x6574, 0x694C),
        "key": (0x1918, 0x1110, 0x0908, 0x0100)})
    witness = model.witness(evaluation)
    assert model.milp_model().is_feasible(witness)
    changed = dict(witness)
    changed[next(iter(changed))] ^= 1
    assert not model.milp_model().is_feasible(changed)


def test_glpk_undefined_status_is_not_an_infeasibility_proof():
    formula = CNFFormula(("x",), ((1,),), ("test",))
    model = cnf_to_milp(formula)
    status, assignment, objective = GLPKSolver._parse_solution("s mip 1 1 u 0\n", model, {1: "x"})
    assert status is MILPStatus.UNKNOWN and assignment is None and objective is None

    class UnknownSolver(GLPKSolver):
        def solve(self, model):
            if isinstance(model, MILPModel):
                return MILPResult(MILPStatus.UNKNOWN, None, None, 0, "", "")
            return super().solve(model)

    with pytest.raises(RuntimeError, match="unknown"):
        UnknownSolver().solve(formula)
