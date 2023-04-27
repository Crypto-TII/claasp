from claasp.ciphers.block_ciphers.kasumi_block_cipher import KasumiBlockCipher


def test_kasumi_block_cipher_test_vector():
    kasumi = KasumiBlockCipher()
    key = 0x9900aabbccddeeff1122334455667788
    plaintext = 0xfedcba0987654321
    ciphertext = 0x514896226caa4f20
    assert kasumi.evaluate([key, plaintext]) == ciphertext