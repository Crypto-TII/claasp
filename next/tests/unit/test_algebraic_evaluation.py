import pytest

from claasp_next import BinaryExtensionField, Cipher, PrimeField, ScalarEvaluator, ValueType
from claasp_next.components import Add, LinearMap, Multiply, Power


def test_prime_field_algebraic_components():
    field = PrimeField(17)
    vector_type = ValueType(field, (2,))
    cipher = Cipher("field_algebra", {"left": vector_type, "right": vector_type})
    cipher.add_round()
    addition = Add((cipher.input("left"), cipher.input("right")), component_id="add_0_0")
    addition_output = cipher.add_component(addition)
    product = Multiply((addition_output, cipher.input("right")), component_id="multiply_0_1")
    product_output = cipher.add_component(product)
    power = Power(product_output, 3, component_id="power_0_2")
    cipher.add_component(power)

    result = ScalarEvaluator().evaluate(cipher, {"left": (15, 3), "right": (5, 4)})

    assert result.value_of("add_0_0") == (3, 7)
    assert result.value_of("multiply_0_1") == (15, 11)
    assert result.value_of("power_0_2") == (9, 5)


def test_aes_field_multiplication_and_linear_map():
    aes_field = BinaryExtensionField(8, 0x11B)
    vector_type = ValueType(aes_field, (2,))
    cipher = Cipher("aes_field", {"state": vector_type})
    cipher.add_round()
    linear_map = LinearMap(
        cipher.input("state"),
        ((2, 3), (1, 1)),
        component_id="linear_map_0_0",
    )
    cipher.add_component(linear_map)

    result = ScalarEvaluator().evaluate(cipher, {"state": (0x57, 0x83)})

    # In the AES field, 2*0x57 = 0xae and 3*0x83 = 0x9e.
    assert result.value_of("linear_map_0_0") == (0x30, 0xD4)


def test_algebraic_components_reject_different_value_types():
    prime = ValueType(PrimeField(17), (1,))
    other_prime = ValueType(PrimeField(19), (1,))
    cipher = Cipher("mixed", {"left": prime, "right": other_prime})

    with pytest.raises(ValueError, match="identical value types"):
        Add((cipher.input("left"), cipher.input("right")), component_id="bad")
