from claasp.cipher_modules.code_generator import (
    generate_bit_based_vectorized_python_code_string,
    generic_c_functions_o_name,
    get_padding_component_bit_based_c_code,
    process_tag,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
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

