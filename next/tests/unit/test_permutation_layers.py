"""Fixed and independently derived checks for reusable permutation layers."""

from claasp_next import Bit, Primitive, ScalarEvaluator, ValueType, Word
from claasp_next.components import gaston_theta, keccak_theta, shift_rows, sigma, xoodoo_theta


def _bits(data: bytes):
    return tuple((byte >> bit) & 1 for byte in data for bit in range(7, -1, -1))


def _bit_string(values):
    return "".join(str(value) for value in values)


def _bit_primitive(name, size, constructor, *args):
    primitive = Primitive(name, {"state": ValueType(Bit(), (size,))})
    primitive.add_round()
    output = primitive.add_component(constructor(primitive.input("state"), *args))
    primitive.set_output(output)
    return primitive


def test_shift_rows_is_a_domain_neutral_row_permutation():
    value_type = ValueType(Word(8), (8,))
    primitive = Primitive("shift_rows", {"state": value_type})
    primitive.add_round()
    output = primitive.add_component(shift_rows(
        primitive.input("state"), 4, (1, 2)
    ))
    primitive.set_output(output)
    assert ScalarEvaluator().evaluate(
        primitive, {"state": tuple(range(8))}
    ).output == (3, 0, 1, 2, 6, 7, 4, 5)


def test_sigma_preserves_legacy_fixed_vector():
    primitive = _bit_primitive("sigma", 4, sigma, (1, 3))
    assert ScalarEvaluator().evaluate(
        primitive, {"state": (1, 0, 0, 0)}
    ).output == (1, 1, 0, 1)


def test_keccak_theta_width_one_has_independently_known_column_diffusion():
    primitive = _bit_primitive("keccak_theta", 25, keccak_theta)
    state = (1,) + (0,) * 24
    expected = tuple(
        int(index == 0 or 5 <= index < 10 or 20 <= index < 25)
        for index in range(25)
    )
    assert ScalarEvaluator().evaluate(primitive, {"state": state}).output == expected


def test_xoodoo_theta_preserves_legacy_fixed_prefix():
    data = bytes.fromhex(
        "1234567890abcdef" * 6
    )
    primitive = _bit_primitive("xoodoo_theta", 384, xoodoo_theta)
    output = ScalarEvaluator().evaluate(primitive, {"state": _bits(data)}).output
    assert _bit_string(output[:10]) == "1111010000"


def test_gaston_theta_preserves_legacy_fixed_prefix():
    primitive = _bit_primitive("gaston_theta", 320, gaston_theta)
    output = ScalarEvaluator().evaluate(
        primitive, {"state": _bits(bytes(range(40)))}
    ).output
    assert _bit_string(output[:70]) == (
        "0011010110100010000110000010011000101100101110110000000100111111001111"
    )
