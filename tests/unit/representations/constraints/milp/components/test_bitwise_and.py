"""Recovered and portable bitwise-AND MILP component models."""

from typing import cast

import pytest

from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.milp import (
    BitwiseAndOneHotMILPModel,
    BitwiseAndXorDifferentialMILPModel,
    BitwiseAndXorLinearMILPModel,
)
from claasp.semantics.cryptanalysis import TrailKind


@pytest.mark.parametrize(
    ("model", "variables", "constraints"),
    (
        (BitwiseAndOneHotMILPModel(2, TrailKind.XOR_DIFFERENTIAL), 22, 10),
        (BitwiseAndOneHotMILPModel(2, TrailKind.XOR_LINEAR), 16, 8),
        (BitwiseAndXorDifferentialMILPModel(2), 8, 8),
        (BitwiseAndXorLinearMILPModel(2), 6, 4),
    ),
)
def test_bitwise_and_milp_formulation_sizes(model, variables, constraints):
    formulation = model.milp_model()
    assert len(formulation.variables) == variables
    assert len(formulation.constraints) == constraints
    assert formulation.constraint_models[0].model.backend is ConstraintBackend.MILP


def test_bitwise_and_milp_validates_configuration():
    with pytest.raises(ValueError, match="positive integer"):
        BitwiseAndXorDifferentialMILPModel(0)
    with pytest.raises(ValueError, match="kind"):
        BitwiseAndOneHotMILPModel(1, cast(TrailKind, "truncated"))
    with pytest.raises(ValueError, match="fit"):
        BitwiseAndXorLinearMILPModel(2).milp_model(left_pattern=4)


def test_bitwise_and_milp_requires_model_before_decoding():
    with pytest.raises(ValueError, match="build"):
        BitwiseAndXorLinearMILPModel(1).decode_transition({})
