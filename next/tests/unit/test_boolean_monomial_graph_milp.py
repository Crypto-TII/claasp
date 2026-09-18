"""Portable whole-graph Boolean monomial reachability models."""

import pytest

from claasp_next.primitives import Simon
from claasp_next.representations.constraints.milp import BooleanMonomialGraphMILPModel


def test_simon_graph_model_has_a_maximum_degree_objective():
    model = BooleanMonomialGraphMILPModel(
        Simon(number_of_rounds=1), 0, "plaintext"
    ).milp_model()
    assert model.objective_sense.value == "maximize"
    assert len(model.objective.terms) == 32
    assert len(model.variables) == 384


def test_simon_graph_model_can_restrict_degree_to_cube_positions():
    model = BooleanMonomialGraphMILPModel(
        Simon(number_of_rounds=2), 0, "plaintext", (0, 2)
    ).milp_model()
    assert dict(model.objective.terms) == {"wire_plaintext_0": 1.0, "wire_plaintext_2": 1.0}
    assert {constraint.name for constraint in model.constraints} >= {
        "exclude_variable_1", "exclude_variable_31"
    }


@pytest.mark.parametrize("positions", ((0, 0), (-1,), (32,)))
def test_simon_graph_model_rejects_invalid_variable_positions(positions):
    with pytest.raises(ValueError, match="variable_positions"):
        BooleanMonomialGraphMILPModel(
            Simon(number_of_rounds=1), 0, "plaintext", positions
        )
