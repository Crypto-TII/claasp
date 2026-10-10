"""Tests for recovered differential-linear SAT boundary relations."""

from itertools import product

import pytest

from claasp.representations.constraints import ConstraintReferenceStatus
from claasp.representations.constraints.sat import (
    DifferentialToTruncatedSATModel,
    TruncatedToLinearSATModel,
)
from claasp.semantics.cryptanalysis import XorDifference, XorMask


def test_differential_to_truncated_matches_the_legacy_truth_table():
    formula = DifferentialToTruncatedSATModel(1).cnf_formula()
    for difference, unknown, value in product((0, 1), repeat=3):
        assignment = {
            "difference_0": difference,
            "truncated_0_unknown": unknown,
            "truncated_0_value": value,
        }
        assert formula.is_satisfied(assignment) is (not unknown and value == difference)


def test_truncated_to_linear_matches_the_legacy_truth_table():
    formula = TruncatedToLinearSATModel(1).cnf_formula()
    for unknown, value, mask in product((0, 1), repeat=3):
        assignment = {
            "truncated_0_unknown": unknown,
            "truncated_0_value": value,
            "mask_0": mask,
        }
        expected = not (unknown and value) and not (unknown and mask)
        assert formula.is_satisfied(assignment) is expected


def test_boundary_models_decode_typed_values():
    upper = DifferentialToTruncatedSATModel(2)
    upper.cnf_formula()
    difference, middle = upper.decode_boundary(
        {
            "difference_0": 1,
            "truncated_0_unknown": 0,
            "truncated_0_value": 1,
            "difference_1": 0,
            "truncated_1_unknown": 0,
            "truncated_1_value": 0,
        }
    )
    assert difference == XorDifference(2, 2)
    assert str(middle) == "10"

    lower = TruncatedToLinearSATModel(2)
    lower.cnf_formula()
    middle, mask = lower.decode_boundary(
        {
            "truncated_0_unknown": 1,
            "truncated_0_value": 0,
            "mask_0": 0,
            "truncated_1_unknown": 0,
            "truncated_1_value": 1,
            "mask_1": 1,
        }
    )
    assert str(middle) == "?1"
    assert mask == XorMask(1, 2)


def test_boundary_models_record_direct_relation_provenance():
    for model in (DifferentialToTruncatedSATModel(1), TruncatedToLinearSATModel(1)):
        application = model.cnf_formula().constraint_models[0]
        assert application.model.analysis_kind == "differential_linear"
        assert application.model.reference_status is ConstraintReferenceStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("model_type", "arguments", "error", "message"),
    (
        (DifferentialToTruncatedSATModel, (0,), ValueError, "positive"),
        (TruncatedToLinearSATModel, (True,), ValueError, "positive"),
        (DifferentialToTruncatedSATModel, (2,), ValueError, "contain 2 bits"),
    ),
)
def test_boundary_models_validate_configuration(model_type, arguments, error, message):
    keywords = {"truncated_pattern": "0"} if "contain" in message else {}
    with pytest.raises(error, match=message):
        model_type(*arguments, **keywords)


def test_boundary_models_validate_binary_pattern_types_and_widths():
    with pytest.raises(TypeError, match="XorDifference"):
        DifferentialToTruncatedSATModel(2, difference=XorMask(0, 2))
    with pytest.raises(ValueError, match="contain 2 bits"):
        TruncatedToLinearSATModel(2, mask=XorMask(0, 1))
