from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher


def test_aes_block_cipher():
    aes = AESBlockCipher()
    assert aes.type == 'block_cipher'
    assert aes.family_name == 'aes_block_cipher'
    assert aes.number_of_rounds == 10
    assert aes.id == 'aes_block_cipher_k128_p128_o128_r10'
    assert aes.component_from(0, 0).id == 'xor_0_0'

    aes = AESBlockCipher(number_of_rounds=4)
    assert aes.number_of_rounds == 4
    assert aes.id == 'aes_block_cipher_k128_p128_o128_r4'
    assert aes.component_from(3, 0).id == 'sbox_3_0'

    aes = AESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=8, state_size=3)
    key = 0x2b7e151628aed2a6ab
    plaintext = 0x6bc1bee22e409f96e9
    ciphertext = 0xf8666f8d0ba0dcfced
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=8, state_size=2)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0xdbbdd038
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=4, state_size=4)
    key = 0x2b7e151628aed2a6
    plaintext = 0x6bc1bee22e409f96
    ciphertext = 0x0e51ff61dac37a78
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=4, state_size=3)
    key = 0b100111100101111110011110010111110000
    plaintext = 0b100111100101111110011110010111110000
    ciphertext = 0x3a54a9d02
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=4, state_size=2)
    key = 0x2b7e
    plaintext = 0x6bc1
    ciphertext = 0xa1fe
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=3, state_size=4)
    key = 0x2b7e151628ae
    plaintext = 0x6bc1bee22e40
    ciphertext = 0x33d9c96fe11c
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=3, state_size=3)
    key = 0b101101101101101101100011011
    plaintext = 0b100001111011110101101100010
    ciphertext = 0x0595c25b
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=3, state_size=2)
    key = 0x2b7
    plaintext = 0x6bc
    ciphertext = 0x2c8
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=2, state_size=4)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0x41bed50e
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=2, state_size=3)
    key = 0b101101101100011011
    plaintext = 0b011110101101100010
    ciphertext = 0x00de3c
    assert aes.evaluate([key, plaintext]) == ciphertext

    aes = AESBlockCipher(word_size=2, state_size=2)
    key = 0x2b
    plaintext = 0x6b
    ciphertext = 0x1f
    assert aes.evaluate([key, plaintext]) == ciphertext
