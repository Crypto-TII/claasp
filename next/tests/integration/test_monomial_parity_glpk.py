"""Complete open-solver monomial-path parity enumeration."""

import pytest

from claasp_next.analysis import enumerate_optimal_monomial_parity
from claasp_next.ciphers import SimonBlockCipher
from claasp_next.drivers.solvers import GLPKSolver
from claasp_next.representations.constraints.milp import BooleanMonomialGraphMILPModel


pytestmark = pytest.mark.external


def test_glpk_complete_parity_matches_exact_two_round_simon_anf():
    compilation = BooleanMonomialGraphMILPModel(
        SimonBlockCipher(number_of_rounds=2), 0, "plaintext"
    )
    result = enumerate_optimal_monomial_parity(compilation, GLPKSolver())
    assert result.degree == 3
    assert result.odd_input_monomials == (
        541065344, 543162368, 2151694336, 2420113408, 2688548864,
    )
    assert result.enumerated_paths == 5
    assert result.complete
    assert result.termination == "exhausted_unsat"


def test_path_limit_cannot_be_mistaken_for_complete_parity():
    compilation = BooleanMonomialGraphMILPModel(
        SimonBlockCipher(number_of_rounds=2), 0, "plaintext"
    )
    result = enumerate_optimal_monomial_parity(
        compilation, GLPKSolver(), max_paths=1
    )
    assert not result.complete
    assert result.termination == "path_limit"
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
