"""Deterministic-truncated CP component construction."""

import pytest

from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.cp import ModularAddDeterministicTruncatedCPModel


def test_deterministic_truncated_cp_preserves_paired_carry_formula():
    model = ModularAddDeterministicTruncatedCPModel(4)
    query = model.cp_model(left_pattern="0001", right_pattern="0001", output_pattern="???0")
    assert len(query.declarations) == 32
    assert len(query.constraints) == 71
    assert query.constraint_models[0].model.backend is ConstraintBackend.CP


def test_deterministic_truncated_cp_validates_boundaries():
    with pytest.raises(ValueError, match="contain 4 bits"):
        ModularAddDeterministicTruncatedCPModel(4).cp_model(left_pattern="0")
    with pytest.raises(ValueError, match="build"):
        ModularAddDeterministicTruncatedCPModel(2).decode_transition({})
