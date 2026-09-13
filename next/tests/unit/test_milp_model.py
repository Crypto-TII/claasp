import pytest

from claasp_next.milp import (
    ConstraintSense, LinearConstraint, LinearExpression, LinearVariable,
    LPExporter, MILPModel, ObjectiveSense, VariableKind,
)


def _knapsack_model():
    variables = tuple(LinearVariable(name, VariableKind.BINARY) for name in ("x", "y", "z"))
    return MILPModel(
        variables,
        (LinearConstraint(LinearExpression.from_terms({"x": 2, "y": 3, "z": 4}), ConstraintSense.LESS_EQUAL, 5, "capacity"),),
        LinearExpression.from_terms({"x": 3, "y": 4, "z": 5}),
        ObjectiveSense.MAXIMIZE,
    )


def test_model_checks_feasibility_and_objective_independently():
    model = _knapsack_model()
    assert model.is_feasible({"x": 1, "y": 1, "z": 0})
    assert model.objective_value({"x": 1, "y": 1, "z": 0}) == 7
    assert not model.is_feasible({"x": 1, "y": 0, "z": 1})
    assert not model.is_feasible({"x": 0.5, "y": 0, "z": 0})


def test_lp_export_is_deterministic_and_declares_domains():
    text = LPExporter().export(_knapsack_model())
    assert text == """Maximize
 objective: 3 x + 4 y + 5 z
Subject To
 capacity: 2 x + 3 y + 4 z <= 5
Bounds
Binary
 x
 y
 z
End
"""


def test_model_rejects_unknown_or_duplicate_variables():
    with pytest.raises(ValueError, match="unique"):
        MILPModel((LinearVariable("x"), LinearVariable("x")), ())
    with pytest.raises(ValueError, match="unknown"):
        MILPModel((LinearVariable("x"),), (), LinearExpression.from_terms({"y": 1}))
