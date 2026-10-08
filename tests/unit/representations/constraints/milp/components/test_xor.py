"""Recovered and compact exact MILP XOR formulations."""

from itertools import product

import pytest

from claasp.representations.constraints.milp import (
    XorImpossiblePointMILPModel,
    XorParityMILPModel,
    xor_arities_for_binary_matrix,
)


@pytest.mark.parametrize("operands", range(2, 8))
def test_xor_formulations_accept_exactly_even_extended_parity(operands):
    for model_type in (XorParityMILPModel, XorImpossiblePointMILPModel):
        relation = model_type(operands)
        model = relation.milp_model()
        for values in product((0, 1), repeat=operands + 1):
            assignment = dict(zip(relation.columns, values))
            if model_type is XorParityMILPModel:
                assignment["parity_quotient"] = sum(values) // 2
            assert model.is_feasible(assignment) is (sum(values) % 2 == 0)


@pytest.mark.parametrize("model_type", (XorParityMILPModel, XorImpossiblePointMILPModel))
def test_xor_formulations_decode_fixed_transition(model_type):
    relation = model_type(4)
    model = relation.milp_model(inputs=(1, 0, 1, 1), output=1)
    assignment = dict(zip(relation.columns, (1, 0, 1, 1, 1)))
    if model_type is XorParityMILPModel:
        assignment["parity_quotient"] = 2
    assert relation.decode_transition(assignment) == ((1, 0, 1, 1), 1)
    assert model.is_feasible(assignment)


def test_matrix_arities_are_computed_without_a_cache():
    matrix = ((1, 1, 1, 0), (1, 1, 0, 1), (0, 1, 1, 1))
    assert xor_arities_for_binary_matrix(matrix) == (2, 3)
