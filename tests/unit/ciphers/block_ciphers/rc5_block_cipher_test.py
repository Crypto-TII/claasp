from claasp.ciphers.block_ciphers.rc5_block_cipher import RC5BlockCipher


def test_rc5_block_cipher():
    rc5 = RC5BlockCipher()
    assert rc5.type == 'block_cipher'
    assert rc5.family_name == 'rc5_block_cipher'
    assert rc5.number_of_rounds == 16
    assert rc5.id == 'rc5_block_cipher_k64_p32_o32_r16'
    assert rc5.component_from(0, 0).id == 'constant_0_0'

    rc5 = RC5BlockCipher(number_of_rounds=4)
    assert rc5.number_of_rounds == 4
    assert rc5.id == 'rc5_block_cipher_k64_p64_o64_r4'
    assert rc5.component_from(3, 1).id == 'xor_3_1'

    rc5 = RC5BlockCipher(word_size=8, number_of_rounds=12, key_size=32)
    key = 0x00010203
    plaintext = 0x0001
    ciphertext = 0x212a
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=16, number_of_rounds=16, key_size=64)
    key = 0x0001020304050607
    plaintext = 0x00010203
    ciphertext = 0x23a8d72e
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=32, number_of_rounds=20, key_size=128)
    key = 0x000102030405060708090A0B0C0D0E0F
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0x2A0EDC0E9431FF73
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=64, number_of_rounds=24, key_size=192)
    key = 0x000102030405060708090A0B0C0D0E0F1011121314151617
    plaintext = 0x000102030405060708090A0B0C0D0E0F
    ciphertext = 0xA46772820EDBCE0235ABEA32AE7178DA
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=128, number_of_rounds=28, key_size=256)
    key = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    plaintext = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    ciphertext = 0xECA5910921A4F4CFDD7AD7AD20A1FCBA068EC7A7CD752D68FE914B7FE180B440
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=24, number_of_rounds=4, key_size=1)
    key = 0x0
    plaintext = 0x000102030405
    ciphertext = 0x89CBDCC9525A
    assert rc5.evaluate([key, plaintext]) == ciphertext

    rc5 = RC5BlockCipher(word_size=80, number_of_rounds=4, key_size=96)
    key = 0x000102030405060708090A0B
    plaintext = 0x000102030405060708090A0B0C0D0E0F10111213
    ciphertext = 0x9CB59ECBA4EA84568A4278B0E132D5FC9D5819D6
    assert rc5.evaluate([key, plaintext]) == ciphertext


