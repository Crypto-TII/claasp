from claasp.cipher_modules import code_generator
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_generate_bit_based_vectorized_python_code_string():
    speck = SpeckBlockCipher()
    string_python_code = code_generator.generate_bit_based_vectorized_python_code_string(speck)

    assert string_python_code.split("\n")[0] == 'from claasp.cipher_modules.generic_functions_vectorized_bit import *'
