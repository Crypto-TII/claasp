import numpy as np

import claasp.cipher_modules.generic_functions_vectorized_bit as gf

from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_AND
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_CONCAT
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_MODADD
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_MODMUL
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_MODSUB
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_NOT
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_OR
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_ROTATE
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_SBOX
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_SHIFT
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_SHIFT_BY_VARIABLE_AMOUNT
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_XOR
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_select_word
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_idea_modmul
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_linear_layer
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_mix_column_poly0
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_permutation
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_print_as_hex_values
from claasp.cipher_modules.generic_functions_vectorized_bit import bit_vector_to_integer


def _bits(value, width):
    result = np.zeros((width, 1), dtype=np.uint8)
    for bit_index in range(width):
        if value & (1 << bit_index):
            result[width - bit_index - 1, 0] = 1
    return result

def test_bit_vector_modmul():
    # Test 1: Standard IDEA multiplication (3 * 5) mod 65537 = 15
    a = np.zeros((16, 1), dtype=np.uint8)
    a[14, 0] = 1  # bit 1
    a[15, 0] = 1  # bit 0 -> value 3
    b = np.zeros((16, 1), dtype=np.uint8)
    b[13, 0] = 1  # bit 2
    b[15, 0] = 1  # bit 0 -> value 5
    result = bit_vector_idea_modmul([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)
    expected[12, 0] = 1  # bit 3
    expected[13, 0] = 1  # bit 2
    expected[14, 0] = 1  # bit 1
    expected[15, 0] = 1  # bit 0 -> value 15
    assert np.array_equal(result, expected)

    # Test 2: Mapping (0 * 1) mod 65537 with 0 representing 2^16
    a = np.zeros((16, 1), dtype=np.uint8)  # 0 treated as 2^16
    b = np.zeros((16, 1), dtype=np.uint8)
    b[15, 0] = 1  # 1
    result = bit_vector_idea_modmul([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)  # Maps back to 0
    assert np.array_equal(result, expected)

    # Test 3: Both operands zero (0 * 0) -> (2^16 * 2^16) mod 65537 = 1
    a = np.zeros((16, 1), dtype=np.uint8)
    b = np.zeros((16, 1), dtype=np.uint8)
    result = bit_vector_idea_modmul([a, b], 2, 16, 65537)
    expected = np.zeros((16, 1), dtype=np.uint8)
    expected[15, 0] = 1  # Result is 1
    assert np.array_equal(result, expected)

def test_bit_vector_modmul_standard():
    # Test (3 * 5) mod 16 = 15
    a = np.zeros((4, 1), dtype=np.uint8)
    a[2, 0] = 1
    a[3, 0] = 1
    b = np.zeros((4, 1), dtype=np.uint8)
    b[1, 0] = 1
    b[3, 0] = 1
    result = bit_vector_MODMUL([a, b], 2, 4)
    expected = np.zeros((4, 1), dtype=np.uint8)
    expected[:, 0] = 1
    assert np.array_equal(result, expected)
    
    # Test (4 * 4) mod 16 = 0
    a = np.zeros((4, 1), dtype=np.uint8)
    a[1, 0] = 1
    result = bit_vector_MODMUL([a, a], 2, 4)
    expected = np.zeros((4, 1), dtype=np.uint8)
    assert np.array_equal(result, expected)


def test_bit_vector_to_integer_and_concat():
    bits = _bits(0b1011, 4)
    assert bit_vector_to_integer(bits)[0] == 11
    assert np.array_equal(bit_vector_CONCAT([bits]), bits)

    first = _bits(0b10, 2)
    second = _bits(0b01, 2)
    concatenated = bit_vector_CONCAT([first, second])
    assert concatenated.shape == (4, 1)
    assert np.array_equal(concatenated, np.vstack([first, second]))


def test_bit_vector_select_word_and_sbox():
    bits = _bits(0b1101, 4)
    assert np.array_equal(bit_vector_select_word(bits, [0, 1, 2, 3]), bits)
    assert np.array_equal(bit_vector_select_word(bits, [3, 2]), bits[[3, 2]])
    assert np.array_equal(bit_vector_select_word(bits, [3, 2], verbosity=True), bits[[3, 2]])

    sbox = np.arange(16, dtype=np.uint8)
    assert np.array_equal(bit_vector_SBOX(bits, sbox), bits)
    assert np.array_equal(bit_vector_SBOX(bits, sbox, output_bit_size=2), _bits(0b01, 2))
    assert np.array_equal(bit_vector_SBOX(bits, sbox, verbosity=True), bits)


def test_bit_vector_xor_and_or_not():
    left = _bits(0b1100, 4)
    right = _bits(0b1010, 4)
    assert np.array_equal(bit_vector_NOT([left]), _bits(0b0011, 4))

    assert np.array_equal(bit_vector_XOR([left, right], 2, 4), _bits(0b0110, 4))
    assert np.array_equal(bit_vector_XOR([_bits(1, 1), _bits(0, 1), _bits(1, 1), _bits(0, 1)], 2, 2), _bits(0, 2))

    assert np.array_equal(bit_vector_AND([left, right], 2, 4), _bits(0b1000, 4))
    assert np.array_equal(bit_vector_OR([left, right], 2, 4), _bits(0b1110, 4))

    concat_inputs = [_bits(0b1, 1), _bits(0b1, 1), _bits(0b0, 1), _bits(0b1, 1)]
    assert np.array_equal(bit_vector_AND(concat_inputs, 2, 2), _bits(0b01, 2))
    assert np.array_equal(bit_vector_OR(concat_inputs, 2, 2), _bits(0b11, 2))
    assert np.array_equal(bit_vector_AND([left, right], 2, 4, verbosity=True), _bits(0b1000, 4))
    assert np.array_equal(bit_vector_OR([left, right], 2, 4, verbosity=True), _bits(0b1110, 4))
    assert np.array_equal(bit_vector_NOT([left], verbosity=True), _bits(0b0011, 4))


def test_bit_vector_rotate_shift_and_permutation():
    bits = _bits(0b1001, 4)
    assert np.array_equal(bit_vector_ROTATE([bits], 1), _bits(0b1100, 4))
    assert np.array_equal(bit_vector_SHIFT([bits], 1), _bits(0b0100, 4))
    assert np.array_equal(bit_vector_SHIFT([bits], -1), _bits(0b0010, 4))
    assert np.array_equal(bit_vector_ROTATE([bits], 1, verbosity=True), _bits(0b1100, 4))
    assert np.array_equal(bit_vector_SHIFT([bits], 1, verbosity=True), _bits(0b0100, 4))

    shifted = bit_vector_SHIFT_BY_VARIABLE_AMOUNT([bits, _bits(1, 4)], 4, 1)
    assert shifted.shape == (4, 1)
    assert bit_vector_SHIFT_BY_VARIABLE_AMOUNT([bits, _bits(1, 4)], 4, -1, verbosity=True).shape == (4, 1)

    assert np.array_equal(bit_vector_permutation([bits], [3, 2, 1, 0]), _bits(0b1001, 4))
    assert np.array_equal(bit_vector_permutation([bits], [3, 2, 1, 0], verbosity=True), _bits(0b1001, 4))
    assert np.array_equal(bit_vector_linear_layer(bits, np.eye(4, dtype=np.uint8)), bits)
    assert np.array_equal(
        bit_vector_linear_layer(bits, np.array([[1, 1, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]], dtype=np.uint8)),
        _bits(0b1101, 4),
    )
    assert np.array_equal(bit_vector_linear_layer(bits, np.eye(4, dtype=np.uint8), verbosity=True), bits)
    assert np.array_equal(
        bit_vector_linear_layer(bits, np.array([[1, 1, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]], dtype=np.uint8), verbosity=True),
        _bits(0b1101, 4),
    )


def test_bit_vector_modadd_modsub_and_idea_modmul():
    a = _bits(0b0011, 4)
    b = _bits(0b0101, 4)
    assert np.array_equal(bit_vector_MODADD([a, b], 2, 4), _bits(0b1000, 4))
    assert np.array_equal(bit_vector_MODSUB([b, a], 2, 4), _bits(0b0010, 4))
    assert np.array_equal(bit_vector_MODADD([_bits(1, 1), _bits(0, 1), _bits(1, 1), _bits(0, 1)], 2, 2), _bits(0, 2))
    assert np.array_equal(bit_vector_MODSUB([b, a], 2, 4, verbosity=True), _bits(0b0010, 4))

    wide_a = _bits(1, 33)
    wide_b = _bits(1, 33)
    assert np.array_equal(bit_vector_MODMUL([wide_a, wide_b], 2, 33), _bits(1, 33))
    assert np.array_equal(bit_vector_idea_modmul([_bits(0, 16), _bits(1, 16)], 2, 16, 65537), _bits(0, 16))
    assert np.array_equal(bit_vector_MODMUL([_bits(1, 1), _bits(0, 1), _bits(1, 1), _bits(0, 1)], 2, 2), _bits(0, 2))
    assert np.array_equal(bit_vector_MODMUL([wide_a, wide_b], 2, 33, verbosity=True), _bits(1, 33))
    assert np.array_equal(bit_vector_idea_modmul([_bits(0, 16), _bits(1, 16)], 2, 16, 65537, verbosity=True), _bits(0, 16))


def test_bit_vector_debug_branches_and_print_helpers():
    previous_debug_mode = gf.DEBUG_MODE
    gf.DEBUG_MODE = True
    try:
        left = _bits(0b1100, 4)
        right = _bits(0b1010, 4)
        assert np.array_equal(gf.bit_vector_XOR([left, right], 2, 4), _bits(0b0110, 4))
        assert np.array_equal(gf.bit_vector_MODADD([left, right], 2, 4), _bits(0b0110, 4))
        assert np.array_equal(gf.bit_vector_MODSUB([_bits(0b0101, 4), _bits(0b0011, 4)], 2, 4), _bits(0b0010, 4))
        assert np.array_equal(gf.bit_vector_MODMUL([_bits(1, 33), _bits(1, 33)], 2, 33), _bits(1, 33))
        assert np.array_equal(gf.bit_vector_idea_modmul([_bits(0, 16), _bits(1, 16)], 2, 16, 65537), _bits(0, 16))
    finally:
        gf.DEBUG_MODE = previous_debug_mode

    bit_vector_print_as_hex_values("hex", [left, right])
    bit_vector_print_as_hex_values("hex", left)


def test_bit_vector_mix_column_poly0():
    bits = _bits(0b1010, 4)
    matrix = np.array([[1, 0], [0, 1]], dtype=np.uint8)
    assert np.array_equal(bit_vector_mix_column_poly0(bits, matrix), bits)
