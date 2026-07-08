from claasp.cipher_modules.code_generator import (
    generate_bit_based_vectorized_python_code_string,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_generate_bit_based_vectorized_python_code_string():
    speck = SpeckBlockCipher()
    string_python_code = generate_bit_based_vectorized_python_code_string(speck)

    assert string_python_code.split("\n")[0] == 'from claasp.cipher_modules.generic_functions_vectorized_bit import *'

