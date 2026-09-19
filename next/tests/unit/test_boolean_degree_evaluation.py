"""Tests for scalable, explicitly inexact Boolean degree propagation."""

from claasp_next.primitives import Simon
from claasp_next.representations.execution import BooleanDegreeEvaluator, BooleanSymbolicEvaluator


def test_degree_propagation_is_a_sound_bound_on_exact_simon_degrees():
    primitive = Simon(number_of_rounds=4)
    bound = BooleanDegreeEvaluator().evaluate(primitive, "plaintext")
    exact = BooleanSymbolicEvaluator().evaluate(primitive)

    assert all(
        polynomial.degree <= upper
        for polynomial, upper in zip(exact.output_anfs, bound.output_bounds)
    )
    assert bound.output_bounds == (16,) * 16 + (8,) * 16
    assert bound.sound
    assert not bound.complete


def test_degree_propagation_scales_to_simon_thirteen():
    result = BooleanDegreeEvaluator().evaluate(Simon(number_of_rounds=13), "plaintext")
    assert result.output_bounds == (32,) * 32


def test_degree_propagation_rejects_unknown_variable_input():
    primitive = Simon(number_of_rounds=1)
    try:
        BooleanDegreeEvaluator().evaluate(primitive, "iv")
    except ValueError as error:
        assert str(error) == "unknown variable input: iv"
    else:
        raise AssertionError("unknown input was accepted")
