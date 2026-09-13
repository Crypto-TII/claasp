import os

from claasp.cipher_modules.code_generator import (
    TII_C_LIB_PATH,
    delete_generated_evaluate_c_shared_library,
    evaluate_c_name,
    generate_bit_based_vectorized_python_code_string,
    generate_evaluate_c_code_shared_library,
    generic_c_functions_o_name,
    get_padding_component_bit_based_c_code,
    process_tag,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
from claasp.ciphers.single_component_ciphers.variable_rotate_cipher import VariableRotateCipher
from claasp.ciphers.single_component_ciphers.variable_shift_cipher import VariableShiftCipher
from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher


def test_generate_bit_based_vectorized_python_code_string():
    speck = SpeckBlockCipher()
    string_python_code = generate_bit_based_vectorized_python_code_string(speck)

    assert string_python_code.split("\n")[0] == 'from claasp.cipher_modules.generic_functions_vectorized_bit import *'


def test_generic_c_functions_o_name():
    tag = process_tag()

    # word-based cipher -> the `if cipher_word_size:` branch
    xtea = XTeaBlockCipher(number_of_rounds=2)
    word_size = xtea.is_power_of_2_word_based()
    assert word_size
    assert generic_c_functions_o_name(xtea) == f"generic_word_{word_size}_based_c_functions_{tag}.o"

    # bit-based cipher -> the `else` branch
    fancy = FancyBlockCipher(number_of_rounds=2)
    assert fancy.is_power_of_2_word_based() is False
    assert generic_c_functions_o_name(fancy) == f"generic_bit_based_c_functions_{tag}.o"


class _StubPaddingComponent:
    """Minimal stand-in exposing only what get_padding_component_bit_based_c_code uses."""
    id = "padding_0_1"
    output_bit_size = 32

    def select_bits(self, code):
        code.append("\t// select_bits\n")

    def print_values(self, code):
        code.append("\t// print_values\n")


def test_get_padding_component_bit_based_c_code():
    component = _StubPaddingComponent()

    code = "".join(get_padding_component_bit_based_c_code(component, verbosity=False))
    assert "\t// select_bits\n" in code                       # component.select_bits(...) called
    assert "BitString* padding_0_1 = PADDING(input, 32);" in code
    assert "delete_bitstring(input);" in code                 # free_input(...) appended
    assert "// print_values" not in code                      # verbosity=False -> no print_values

    code_verbose = "".join(get_padding_component_bit_based_c_code(component, verbosity=True))
    assert "// print_values" in code_verbose                  # verbosity=True -> print_values called


def test_generate_evaluate_c_code_shared_library_word_based():
    # XTea is power-of-2 word-based -> exercises the `if cipher_word_size:` branch
    xtea = XTeaBlockCipher(number_of_rounds=2)
    assert xtea.is_power_of_2_word_based()

    c_file = TII_C_LIB_PATH + evaluate_c_name(xtea) + ".c"
    o_file = TII_C_LIB_PATH + evaluate_c_name(xtea) + ".o"
    generic_o = TII_C_LIB_PATH + generic_c_functions_o_name(xtea)
    try:
        generate_evaluate_c_code_shared_library(xtea, intermediate_output=False, verbosity=False)

        assert os.path.exists(c_file)
        assert os.path.exists(o_file)
        assert os.path.exists(generic_o)
        with open(c_file) as generated_c:
            assert 'generic_word_based_c_functions.h' in generated_c.read()
    finally:
        delete_generated_evaluate_c_shared_library(xtea)


def test_evaluate_using_c_select_bits_with_256_inputs():
    # Regression test for generic_bit_based_c_functions.c's select_bits(): its first
    # parameter n (the number of distinct input BitStrings wired into the component,
    # i.e. len(component.input_id_links)) used to be a uint8_t. code_generator.py bakes
    # n in as a plain C integer literal (component.select_bits() in claasp/component.py),
    # so a component fed by 256+ distinct inputs got n truncated to 0 at the call site
    # (256 % 256 == 0), silently corrupting the result. An XorCipher wired from 256
    # separate 1-bit inputs into a single XOR component reproduces this exactly.
    number_of_inputs = 256
    xor_256 = XorCipher(word_bit_size=1, number_of_inputs=number_of_inputs)
    # XorCipher's auto-generated id embeds one token per input, which is far too long
    # for the filesystem once there are 256 of them (generated C files are named after
    # it); give it a short id purely for file naming, which is otherwise independent of
    # cipher evaluation.
    xor_256.id = "xor_cipher_256_inputs_regression"
    # Non-trivial, non-uniform input with an odd number of 1s (so the correct XOR of
    # all 256 single-bit inputs is 1, not 0 -- a discriminative choice, since a broken
    # select_bits() that silently drops all inputs would otherwise also yield 0).
    inputs = [1 if i < 129 else 0 for i in range(number_of_inputs)]

    expected = xor_256.evaluate(inputs)
    actual = xor_256.evaluate_using_c(inputs)

    assert actual == expected


def test_evaluate_using_c_variable_shift_with_wide_input():
    # Regression test for generic_bit_based_c_functions.c's SHIFT_BY_VARIABLE_AMOUNT():
    # the byte index `i` used to extract the shift amount from the tail of the input
    # BitString used to be a uint8_t, so it wrapped for inputs wider than 255 bytes
    # (2040 bits), reading the wrong byte(s) and producing a silently wrong shift amount.
    # Use an 8192-bit (1024-byte) input, comfortably over that threshold, matching the
    # real scenario (a Blowfish key-dependent S-box prototype) that uncovered the bug.
    # The variable amount itself is kept to 16 bits (2 bytes): that is all the generic C
    # helper ever reads to determine the shift amount (see the `list[i] | list[i-1] << 8`
    # tail extraction), so this keeps the C and pure-Python implementations comparable
    # while still pushing the *total* input comfortably past the 255-byte/uint8_t range.
    bit_size = 8176
    amount_bit_size = 16
    variable_shift = VariableShiftCipher(bit_size=bit_size, amount_bit_size=amount_bit_size, direction=1)

    plaintext = int.from_bytes(bytes([i % 256 for i in range(bit_size // 8)]), byteorder="big")
    shift_amount = 0xBEEF

    expected = variable_shift.evaluate([plaintext, shift_amount])
    actual = variable_shift.evaluate_using_c([plaintext, shift_amount])

    assert actual == expected


def test_evaluate_using_c_variable_rotate_with_wide_input():
    # Same regression as test_evaluate_using_c_variable_shift_with_wide_input, but for
    # ROTATE_BY_VARIABLE_AMOUNT(), which has the identical uint8_t byte-index bug.
    bit_size = 8176
    amount_bit_size = 16
    variable_rotate = VariableRotateCipher(bit_size=bit_size, amount_bit_size=amount_bit_size, direction=1)

    plaintext = int.from_bytes(bytes([i % 256 for i in range(bit_size // 8)]), byteorder="big")
    rotation_amount = 0xBEEF

    expected = variable_rotate.evaluate([plaintext, rotation_amount])
    actual = variable_rotate.evaluate_using_c([plaintext, rotation_amount])

    assert actual == expected

