"""Deterministic-truncated SMT component construction."""

import pytest

from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.smt import ModularAddDeterministicTruncatedSMTModel


def test_deterministic_truncated_smt_preserves_paired_carry_formula():
    model = ModularAddDeterministicTruncatedSMTModel(4)
    formula = model.smt_formula(left_pattern="0001", right_pattern="0001", output_pattern="???0")
    assert len(formula.variables) == 32
    assert formula.assertion_count == 71
    assert formula.constraint_models[0].model.backend is ConstraintBackend.SMT


def test_deterministic_truncated_smt_validates_boundaries():
    model = ModularAddDeterministicTruncatedSMTModel(4)
    with pytest.raises(ValueError, match="contain 4 bits"):
        model.smt_formula(left_pattern="0")
    with pytest.raises(ValueError, match="build"):
        ModularAddDeterministicTruncatedSMTModel(2).decode_transition({})
