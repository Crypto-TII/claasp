from itertools import product

import pytest

from claasp.primitives import AES
from claasp.primitives.single_component_primitives import (
    BinaryAffineMap,
    LinearMap,
    Multiply,
    Power,
    SBox,
)
from claasp.representations.constraints.sat import BooleanCNFModel, BooleanNativeXorModel
from claasp.unit_types import BinaryExtensionField


def _polynomial_product(left, right, degree, modulus):
    raw = 0
    for bit in range(degree):
        if right & (1 << bit):
            raw ^= left << bit
    while raw.bit_length() > degree:
        raw ^= modulus << (raw.bit_length() - degree - 1)
    return raw


@pytest.mark.parametrize("degree,modulus", [(2, 0b111), (3, 0b1011), (4, 0b10011)])
def test_field_multiplication_matches_independent_polynomial_long_division(degree, modulus):
    primitive = Multiply(BinaryExtensionField(degree, modulus))
    for backend in (BooleanCNFModel, BooleanNativeXorModel):
        model = backend(primitive)
        formula = model.cnf_formula()
        for left, right in product(range(1 << degree), repeat=2):
            evaluation = primitive.evaluate_with_trace(left, right)
            assert primitive.evaluate(left, right) == _polynomial_product(
                left, right, degree, modulus
            )
            witness = model.witness(evaluation)
            assert formula.is_satisfied(witness)
            output_bit = next(name for name in witness if name.startswith("multiply_"))
            modified = {**witness, output_bit: 1 - witness[output_bit]}
            assert not formula.is_satisfied(modified)


@pytest.mark.parametrize(
    "primitive",
    [
        LinearMap(((0, 0), (1, 1))),
        LinearMap(((1, 2), (3, 1)), unit_type=BinaryExtensionField(2, 7)),
        BinaryAffineMap(((1, 1), (1, 0)), 3, word_size=2),
        Power(7, BinaryExtensionField(3, 11)),
        SBox((0, 1, 1, 0), unit_type=BinaryExtensionField(2, 7)),
    ],
)
def test_linear_affine_power_and_lookup_witnesses_cover_all_input_values(primitive):
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    width = next(iter(primitive.graph.input_arrays.values())).array_type.encoded_bit_size
    for value in range(1 << width):
        assert formula.is_satisfied(model.witness(primitive.evaluate_with_trace(value)))


def test_full_native_aes_graph_witness_includes_key_schedule_and_field_linear_layers():
    primitive = AES(number_of_rounds=2)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for plaintext, key in (
        (0, 0),
        (0x123456789ABCDEF, 0xFEDCBA987654321),
        ((1 << 128) - 1, (1 << 128) - 1),
    ):
        assert formula.is_satisfied(model.witness(primitive.evaluate_with_trace(plaintext, key)))
