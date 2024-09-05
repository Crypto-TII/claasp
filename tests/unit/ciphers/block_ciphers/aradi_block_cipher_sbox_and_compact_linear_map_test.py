from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox_and_compact_linear_map import (
    AradiBlockCipherSBoxAndCompactLinearMap)


def test_aradi_block_cipher_sbox_and_compact_linear_map():
    aradi = AradiBlockCipherSBoxAndCompactLinearMap()
    plaintext = 0
    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    ciphertext = 0x3f09abf400e3bd7403260defb7c53912
    assert aradi.evaluate([plaintext, key]) == ciphertext
    assert aradi.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
