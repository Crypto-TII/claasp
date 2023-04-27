from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.component_analysis_tests import generate_boolean_polynomial_ring_from_cipher


def test_generate_boolean_polynomial_ring_from_cipher():
    fancy = FancyBlockCipher(number_of_rounds=3)
    generate_boolean_polynomial_ring_from_cipher(fancy)