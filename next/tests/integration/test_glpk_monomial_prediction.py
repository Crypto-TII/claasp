"""Open-source solver integration for exact monomial transitions."""

from claasp_next.drivers.solvers import GLPKSolver, MILPStatus
from claasp_next.representations.constraints.milp import MonomialTransitionMILPModel


PRESENT = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)


def test_glpk_accepts_exact_and_rejects_impossible_present_monomial_transitions():
    representation = MonomialTransitionMILPModel(PRESENT)
    output_mask = 1
    possible = min(representation.table[output_mask])
    impossible = next(mask for mask in range(16) if mask not in representation.table[output_mask])
    solver = GLPKSolver(timeout_seconds=10)

    accepted = solver.solve(representation.milp_model(possible, output_mask))
    rejected = solver.solve(representation.milp_model(impossible, output_mask))

    assert accepted.status is MILPStatus.OPTIMAL
    assert accepted.assignment is not None
    assert rejected.status is MILPStatus.INFEASIBLE
