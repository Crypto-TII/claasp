"""Independent binary and field-word feedback-register checks."""

from itertools import product

import pytest

from claasp_next import (
    BinaryExtensionField,
    Bit,
    Primitive,
    ScalarEvaluator,
    TransposedBatchEvaluator,
    ValueType,
    Word,
)
from claasp_next.components import (
    FeedbackRegister,
    FeedbackRegisterParameters,
    FeedbackRegisterSpec,
    FeedbackTerm,
)
from claasp_next.primitives.single_component_primitives import (
    FeedbackRegister as FeedbackRegisterPrimitive,
)


def _primitive(domain, unit_count, spec, clocks=1):
    primitive = Primitive(
        "feedback_register", {"state": ValueType(domain, (unit_count,))}
    )
    primitive.add_round()
    output = primitive.add_component(
        FeedbackRegister(primitive.input("state"), (spec,), clocks=clocks)
    )
    primitive.set_output(output)
    return primitive


def test_binary_lfsr_matches_complete_legacy_truth_table():
    spec = FeedbackRegisterSpec(4, (FeedbackTerm((0,)), FeedbackTerm((1,))))
    primitive = _primitive(Bit(), 4, spec)
    for state in product(range(2), repeat=4):
        expected = (state[1], state[2], state[3], state[0] ^ state[1])
        assert (
            ScalarEvaluator().evaluate(primitive, {"state": state}).output == expected
        )


def test_typed_feedback_parameters_accept_natural_lists_and_tap_positions():
    parameters = FeedbackRegisterParameters.from_taps(4, [0, 1])
    assert FeedbackRegisterPrimitive(parameters).evaluate(0b1010) == 0b0101

    spec = FeedbackRegisterSpec(4, [FeedbackTerm(0), FeedbackTerm([1])])
    assert _primitive(Bit(), 4, spec).evaluate(0b1010) == 0b0101


def test_clocked_nonlinear_register_updates_only_when_clock_polynomial_is_one():
    spec = FeedbackRegisterSpec(
        4,
        (FeedbackTerm((0,)), FeedbackTerm((1,))),
        clock=(FeedbackTerm((0,)),),
    )
    primitive = _primitive(Bit(), 4, spec)
    for state in product(range(2), repeat=4):
        expected = (
            (state[1], state[2], state[3], state[0] ^ state[1]) if state[0] else state
        )
        assert (
            ScalarEvaluator().evaluate(primitive, {"state": state}).output == expected
        )


def test_field_word_register_uses_declared_binary_extension_field():
    field = BinaryExtensionField(2, 0b111)
    spec = FeedbackRegisterSpec(2, (FeedbackTerm((0,)), FeedbackTerm((1,))))
    primitive = _primitive(field, 2, spec)
    for left, right in product(range(4), repeat=2):
        assert ScalarEvaluator().evaluate(
            primitive, {"state": (left, right)}
        ).output == (right, left ^ right)


def test_multiple_clocks_and_transposed_batch_match_independent_iteration():
    spec = FeedbackRegisterSpec(4, (FeedbackTerm((0,)), FeedbackTerm((1,))))
    primitive = _primitive(Bit(), 4, spec, clocks=3)
    inputs = {"state": tuple(product(range(2), repeat=4))}

    def reference(state):
        for _ in range(3):
            state = (state[1], state[2], state[3], state[0] ^ state[1])
        return state

    expected = tuple(reference(state) for state in inputs["state"])
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected


def test_inverse_field_word_register_recovers_nonunit_pivot():
    field = BinaryExtensionField(2, 0b111)
    spec = FeedbackRegisterSpec(
        2, (FeedbackTerm((0,), coefficient=2), FeedbackTerm((1,))),
    )
    forward = _primitive(field, 2, spec, clocks=2)
    inverse = Primitive("inverse", {"state": ValueType(field, (2,))})
    inverse.add_round()
    inverse.set_output(inverse.add_component(FeedbackRegister(
        inverse.input("state"), (spec,), clocks=2, direction="inverse",
    )))

    for state in product(range(4), repeat=2):
        encoded = state[0] << 2 | state[1]
        assert inverse.evaluate(forward.evaluate(encoded)) == encoded


def test_feedback_register_validation_rejects_ambiguous_word_arithmetic():
    primitive = Primitive("invalid", {"state": ValueType(Word(4), (2,))})
    spec = FeedbackRegisterSpec(2, (FeedbackTerm((0,)),))
    with pytest.raises(ValueError, match="Bit or BinaryExtensionField"):
        FeedbackRegister(primitive.input("state"), (spec,))

    bit_primitive = Primitive("invalid_positions", {"state": ValueType(Bit(), (2,))})
    with pytest.raises(ValueError, match="outside"):
        FeedbackRegister(
            bit_primitive.input("state"),
            (FeedbackRegisterSpec(2, (FeedbackTerm((2,)),)),),
        )
