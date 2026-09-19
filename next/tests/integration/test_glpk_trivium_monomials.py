"""Scalable Trivium IV-degree bounds and complete parity through real GLPK.

The optimal monomial-reachability objective is a sound upper bound only.  Each
test therefore compares it with the exact ANF recovered independently by the
symbolic evaluator, and accepts a parity result as exact only when the
enumeration terminated in UNSAT.
"""

import pytest

from claasp_next.analysis import enumerate_optimal_monomial_parity
from claasp_next.drivers.solvers import GLPKSolver, MILPStatus
from claasp_next.primitives import Trivium
from claasp_next.representations.constraints.milp import BooleanMonomialGraphMILPModel
from claasp_next.representations.execution import BooleanSymbolicEvaluator

pytestmark = pytest.mark.external


def _exact_iv_monomials(primitive):
    """Return the exact top-IV-degree monomials as MSB-first 80-bit masks."""

    polynomial = BooleanSymbolicEvaluator().evaluate(primitive).output_anfs[0]
    positions = {
        term: tuple(int(variable[1:]) for variable in term.variables if variable.startswith("i"))
        for term in polynomial.monomials
    }
    degree = max(len(entry) for entry in positions.values())
    masks = set()
    for term, iv_positions in positions.items():
        if len(iv_positions) == degree and len(term.variables) == degree:
            masks.add(sum(1 << (79 - position) for position in iv_positions))
    return degree, tuple(sorted(masks))


@pytest.mark.parametrize("clocks, expected_degree", ((160, 2), (200, 3)))
def test_glpk_monomial_reachability_bounds_the_exact_iv_degree(clocks, expected_degree):
    primitive = Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=1)
    model = BooleanMonomialGraphMILPModel(primitive, 0, "iv").milp_model()
    exact_degree, _ = _exact_iv_monomials(primitive)

    solved = GLPKSolver(timeout_seconds=60).solve(model)

    assert solved.status is MILPStatus.OPTIMAL
    assert exact_degree == expected_degree
    assert exact_degree <= int(round(solved.objective_value))


@pytest.mark.parametrize("clocks, expected_degree", ((160, 2), (200, 3)))
def test_glpk_complete_parity_matches_the_exact_trivium_anf(clocks, expected_degree):
    primitive = Trivium(number_of_initialization_clocks=clocks, keystream_bit_size=1)
    compilation = BooleanMonomialGraphMILPModel(primitive, 0, "iv")
    exact_degree, exact_masks = _exact_iv_monomials(primitive)

    result = enumerate_optimal_monomial_parity(compilation, GLPKSolver(timeout_seconds=60))

    assert result.complete and result.termination == "exhausted_unsat"
    assert result.require_complete() is result
    assert result.degree == expected_degree == exact_degree
    assert result.odd_input_monomials == exact_masks
    assert result.enumerated_paths == 4


def test_trivium_parity_path_limit_is_not_a_complete_proof():
    compilation = BooleanMonomialGraphMILPModel(
        Trivium(number_of_initialization_clocks=160, keystream_bit_size=1), 0, "iv"
    )

    result = enumerate_optimal_monomial_parity(
        compilation, GLPKSolver(timeout_seconds=60), max_paths=1
    )

    assert not result.complete and result.termination == "path_limit"
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
