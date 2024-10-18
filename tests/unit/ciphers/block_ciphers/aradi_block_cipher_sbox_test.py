from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox


def test_aradi_block_cipher_sbox():
    """
    Tests the ARADI block cipher's S-box implementation using a known test vector from [GreMW24].

    This test checks both the Python evaluation and the vectorized evaluation
    of CLAASP to ensure consistency with the expected output.

    The results are asserted to match the expected ciphertext in both
    evaluation methods.
    """
    aradi = AradiBlockCipherSBox()
    plaintext = 0
    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    ciphertext = 0x3f09abf400e3bd7403260defb7c53912
    assert aradi.evaluate([plaintext, key]) == ciphertext
    assert aradi.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
