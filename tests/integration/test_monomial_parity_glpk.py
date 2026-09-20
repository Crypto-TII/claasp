"""Complete open-solver monomial-path parity enumeration."""

import pytest

from claasp.analysis import enumerate_optimal_monomial_parity
from claasp.drivers.solvers import GLPKSolver
from claasp.primitives import Simon
from claasp.representations.constraints.milp import BooleanMonomialGraphMILPModel

pytestmark = pytest.mark.external


def test_glpk_complete_parity_matches_exact_two_round_simon_anf():
    compilation = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=2), 0, "plaintext")
    result = enumerate_optimal_monomial_parity(compilation, GLPKSolver())
    assert result.degree == 3
    assert result.odd_input_monomials == (
        541065344,
        543162368,
        2151694336,
        2420113408,
        2688548864,
    )
    assert result.enumerated_paths == 5
    assert result.complete
    assert result.termination == "exhausted_unsat"


def test_path_limit_cannot_be_mistaken_for_complete_parity():
    compilation = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=2), 0, "plaintext")
    result = enumerate_optimal_monomial_parity(compilation, GLPKSolver(), max_paths=1)
    assert not result.complete
    assert result.termination == "path_limit"
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
