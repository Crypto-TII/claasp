"""Independent checks for binary and extension-field linear layers."""

from itertools import product

import pytest

from claasp_next import (
    BinaryExtensionField, Bit, Primitive, ScalarEvaluator, TransposedBatchEvaluator,
    ValueType,
)
from claasp_next.components import LinearMap


def _map_primitive(domain, matrix):
    primitive = Primitive("linear_map", {"state": ValueType(domain, (len(matrix[0]),))})
    primitive.add_round()
    output = primitive.add_component(LinearMap(primitive.input("state"), matrix))
    primitive.set_output(output)
    return primitive


def _reference_binary_field_multiply(left, right, degree, modulus):
    polynomial = 0
    for bit in range(degree):
        if right & (1 << bit):
            polynomial ^= left << bit
    for bit in range(polynomial.bit_length() - 1, degree - 1, -1):
        if polynomial & (1 << bit):
            polynomial ^= modulus << (bit - degree)
    return polynomial


def test_binary_linear_map_matches_complete_truth_table():
    primitive = _map_primitive(Bit(), ((1, 1), (1, 0)))
    for left, right in product(range(2), repeat=2):
        assert ScalarEvaluator().evaluate(
            primitive, {"state": (left, right)}
        ).output == (left ^ right, left)


def test_mix_column_style_matrix_matches_independent_gf16_reference():
    field = BinaryExtensionField(4, 0b10011)
    matrix = ((1, 2), (3, 1))
    primitive = _map_primitive(field, matrix)
    for left, right in product(range(16), repeat=2):
        expected = (
            left ^ _reference_binary_field_multiply(right, 2, 4, 0b10011),
            _reference_binary_field_multiply(left, 3, 4, 0b10011) ^ right,
        )
        assert ScalarEvaluator().evaluate(
            primitive, {"state": (left, right)}
        ).output == expected


def test_aes_mix_columns_published_column_and_batch_parity():
    field = BinaryExtensionField(8, 0x11B)
    matrix = (
        (2, 3, 1, 1),
        (1, 2, 3, 1),
        (1, 1, 2, 3),
        (3, 1, 1, 2),
    )
    primitive = _map_primitive(field, matrix)
    inputs = {"state": ((0xD4, 0xBF, 0x5D, 0x30), (0, 0, 0, 0))}
    batch = TransposedBatchEvaluator().evaluate(primitive, inputs)
    assert batch.outputs == ((0x04, 0x66, 0x81, 0xE5), (0, 0, 0, 0))
    assert batch.outputs == tuple(
        ScalarEvaluator().evaluate(primitive, {"state": state}).output
        for state in inputs["state"]
    )


def test_linear_map_rejects_bad_shapes_and_noncanonical_coefficients():
    primitive = Primitive("invalid", {"state": ValueType(Bit(), (2,))})
    with pytest.raises(ValueError, match="2 coefficients"):
        LinearMap(primitive.input("state"), ((1,),))
    with pytest.raises(ValueError, match="canonical element"):
        LinearMap(primitive.input("state"), ((1, 2),))
