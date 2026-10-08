import pytest

from claasp import BinaryExtensionField, PrimeField, Primitive, ScalarEvaluator, ValueType
from claasp.components import Add, BinaryAffineMap, LinearMap, Multiply, Power


def test_prime_field_algebraic_components():
    field = PrimeField(17)
    vector_type = ValueType(field, (2,))
    primitive = Primitive("field_algebra", {"left": vector_type, "right": vector_type})
    primitive._builder.add_round()
    addition = Add((primitive.input("left"), primitive.input("right")), component_id="add_0_0")
    addition_output = primitive._builder.add_component(addition)
    product = Multiply((addition_output, primitive.input("right")), component_id="multiply_0_1")
    product_output = primitive._builder.add_component(product)
    power = Power(product_output, 3, component_id="power_0_2")
    primitive._builder.add_component(power)

    result = ScalarEvaluator().evaluate(primitive, {"left": (15, 3), "right": (5, 4)})

    assert result.value_of("add_0_0") == (3, 7)
    assert result.value_of("multiply_0_1") == (15, 11)
    assert result.value_of("power_0_2") == (9, 5)


def test_aes_field_multiplication_and_linear_map():
    aes_field = BinaryExtensionField(8, 0x11B)
    vector_type = ValueType(aes_field, (2,))
    primitive = Primitive("aes_field", {"state": vector_type})
    primitive._builder.add_round()
    linear_map = LinearMap(
        primitive.input("state"),
        ((2, 3), (1, 1)),
        component_id="linear_map_0_0",
    )
    primitive._builder.add_component(linear_map)

    result = ScalarEvaluator().evaluate(primitive, {"state": (0x57, 0x83)})

    # In the AES field, 2*0x57 = 0xae and 3*0x83 = 0x9e.
    assert result.value_of("linear_map_0_0") == (0x30, 0xD4)


def test_algebraic_components_reject_different_value_types():
    prime = ValueType(PrimeField(17), (1,))
    other_prime = ValueType(PrimeField(19), (1,))
    primitive = Primitive("mixed", {"left": prime, "right": other_prime})

    with pytest.raises(ValueError, match="identical value types"):
        Add((primitive.input("left"), primitive.input("right")), component_id="bad")


def test_binary_affine_map_composes_with_field_inverse_to_form_aes_sbox():
    from claasp.primitives.block_ciphers.aes import AES_AFFINE_MATRIX, AES_SBOX

    field = BinaryExtensionField(8, 0x11B)
    primitive = Primitive("aes_substitution", {"values": ValueType(field, (256,))})
    primitive._builder.add_round()
    inverse = primitive._builder.add_component(Power(primitive.input("values"), 254))
    affine = primitive._builder.add_component(BinaryAffineMap(inverse, AES_AFFINE_MATRIX, 0x63))
    primitive._builder.set_output(affine)

    result = ScalarEvaluator().evaluate(primitive, {"values": tuple(range(256))})
    assert result.output == AES_SBOX
