"""Independent arithmetic checks for the reusable word/ARX catalogue."""

from itertools import product

import pytest

from claasp import ArrayType, Primitive, ScalarEvaluator, TransposedBatchEvaluator
from claasp.components import (
    IDEAMultiply,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
)
from claasp.domains import Word


def _binary_primitive(component_type, width=3, **kwargs):
    array_type = ArrayType(Word(width), (1,))
    primitive = Primitive(component_type.__name__, {"left": array_type, "right": array_type})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        component_type((primitive.graph.input("left"), primitive.graph.input("right")), **kwargs)
    )
    primitive._builder.set_output(output)
    return primitive


@pytest.mark.parametrize(
    ("component_type", "expected"),
    [
        (ModularAdd, lambda left, right: (left + right) & 7),
        (ModularSubtract, lambda left, right: (left - right) & 7),
        (ModularMultiply, lambda left, right: (left * right) & 7),
    ],
)
def test_modular_operations_match_exhaustive_three_bit_arithmetic(component_type, expected):
    primitive = _binary_primitive(component_type)
    for left, right in product(range(8), repeat=2):
        result = ScalarEvaluator().evaluate(primitive, {"left": (left,), "right": (right,)}).output
        assert result == (expected(left, right),)


def test_modular_multiply_honors_non_power_of_two_modulus():
    primitive = _binary_primitive(ModularMultiply, width=4, modulus=13)
    assert ScalarEvaluator().evaluate(primitive, {"left": (11,), "right": (7,)}).output == (12,)


def test_idea_multiplication_matches_zero_encoded_field_arithmetic():
    primitive = _binary_primitive(IDEAMultiply)
    for left, right in product(range(8), repeat=2):
        encoded_left = 8 if left == 0 else left
        encoded_right = 8 if right == 0 else right
        product_value = encoded_left * encoded_right % 9
        expected = 0 if product_value == 8 else product_value
        assert ScalarEvaluator().evaluate(
            primitive, {"left": (left,), "right": (right,)}
        ).output == (expected,)


def _motion_primitive(component_type, direction, *, variable=False):
    values = ArrayType(Word(8), (2,))
    inputs = {"values": values}
    if variable:
        inputs["amount"] = ArrayType(Word(4), (1,))
    primitive = Primitive(component_type.__name__, inputs)
    primitive._builder.add_round()
    if variable:
        component = component_type(
            primitive.graph.input("values"), primitive.graph.input("amount"), direction
        )
    else:
        component = component_type(primitive.graph.input("values"), 3, direction)
    output = primitive._builder.add_component(component)
    primitive._builder.set_output(output)
    return primitive


@pytest.mark.parametrize(
    ("component_type", "variable", "direction", "expected"),
    [
        (Shift, False, "left", (0x90, 0x08)),
        (Shift, False, "right", (0x06, 0x04)),
        (Rotate, False, "left", (0x91, 0x09)),
        (Rotate, False, "right", (0x46, 0x24)),
        (VariableShift, True, "left", (0x90, 0x08)),
        (VariableShift, True, "right", (0x06, 0x04)),
        (VariableRotate, True, "left", (0x91, 0x09)),
        (VariableRotate, True, "right", (0x46, 0x24)),
    ],
)
def test_fixed_and_variable_word_motion(component_type, variable, direction, expected):
    primitive = _motion_primitive(component_type, direction, variable=variable)
    inputs = {"values": (0x32, 0x21)}
    if variable:
        inputs["amount"] = (3,)
    assert ScalarEvaluator().evaluate(primitive, inputs).output == expected


def test_shift_saturates_while_rotation_reduces_amount_modulo_width():
    array_type = ArrayType(Word(8), (1,))
    shifted = Primitive("shift", {"value": array_type})
    shifted._builder.add_round()
    shifted._builder.set_output(
        shifted._builder.add_component(Shift(shifted.graph.input("value"), 11, "left"))
    )
    rotated = Primitive("rotate", {"value": array_type})
    rotated._builder.add_round()
    rotated._builder.set_output(
        rotated._builder.add_component(Rotate(rotated.graph.input("value"), 11, "left"))
    )
    assert ScalarEvaluator().evaluate(shifted, {"value": (0x32,)}).output == (0,)
    assert ScalarEvaluator().evaluate(rotated, {"value": (0x32,)}).output == (0x91,)


def test_new_word_operations_have_transposed_batch_parity():
    primitive = _motion_primitive(VariableShift, "right", variable=True)
    inputs = {
        "values": ((0x80, 0x55), (0xFF, 0x10), (0x01, 0x80)),
        "amount": ((0,), (4,), (9,)),
    }
    expected = ((0x80, 0x55), (0x0F, 0x01), (0, 0x40))
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected


def test_variable_amount_and_modulus_validation_are_explicit():
    array_type = ArrayType(Word(8), (1,))
    amounts = ArrayType(Word(4), (2,))
    primitive = Primitive("validation", {"value": array_type, "amount": amounts})
    with pytest.raises(ValueError, match="exactly one word"):
        VariableRotate(primitive.graph.input("value"), primitive.graph.input("amount"), "left")
    with pytest.raises(ValueError, match="2..256"):
        ModularMultiply(
            (primitive.graph.input("value"), primitive.graph.input("value")), modulus=257
        )
