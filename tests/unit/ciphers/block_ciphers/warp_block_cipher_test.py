from claasp.ciphers.block_ciphers.warp_block_cipher import WarpBlockCipher


def test_warp_block_cipher():
    """Test warp block cipher for 41 rounds with test vectors from [WARP]_."""
    warp = WarpBlockCipher()
    assert warp.type == 'block_cipher'
    assert warp.family_name == 'warp'
    assert warp.number_of_rounds == 41

    plaintext = 0x00112233445566778899aabbccddeeff
    key = 0x0123456789abcdeffedcba9876543210
    ciphertext = 0x923c64f92827ee62b9667dd2548fb12c
    assert warp.evaluate([plaintext, key]) == ciphertext
    assert warp.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    plaintext = 0xaf6cdd90fc5a6eaa897bcd1208d391e1
    key = 0x0acd022f680a547fee03c0867b09e3d7
    ciphertext = 0x6123995f1924d31425641acdd058dd46

    assert warp.evaluate([plaintext, key]) == ciphertext
    assert warp.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
