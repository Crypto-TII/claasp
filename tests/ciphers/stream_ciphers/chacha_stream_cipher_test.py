from claasp.ciphers.stream_ciphers.chacha_stream_cipher import ChachaStreamCipher


def test_chacha_stream_cipher():
    chacha = ChachaStreamCipher()
    assert chacha.family_name == 'chacha_stream_cipher'
    assert chacha.type == 'stream_cipher'
    assert chacha.number_of_rounds == 20
    assert chacha.id == 'chacha_stream_cipher_p512_k256_n96_o512_r20'
    assert chacha.component_from(0, 0).id == 'modadd_0_0'

    chacha = ChachaStreamCipher(number_of_rounds=4)
    assert chacha.number_of_rounds == 4
    assert chacha.id == 'chacha_stream_cipher_p512_k256_n96_o512_r4'
    assert chacha.component_from(3, 0).id == 'modadd_3_0'

    cipher = ChachaStreamCipher(number_of_rounds=40)
    cipher.sort_cipher()
    state = ["61707865", "3320646e", "79622d32", "6b206574",
             "03020100", "07060504", "0b0a0908", "0f0e0d0c",
             "13121110", "17161514", "1b1a1918", "1f1e1d1c",
             "00000001", "09000000", "4a000000", "00000000"]
    plaintext = int("0x" + "".join(state), 16)
    key = int("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 16)
    nonce = int("0x000000090000004a00000000", 16)
    ciphertext = int("0xe4e7f11015593bd11fdd0f50c47120a3c7f4d1c70368c0339aaa22044e6cd4c3466482d209aa9f"
                     "0705d7c214a2028bd9d19c12b5b94e16dee883d0cb4e3c50a2", 16)
    assert cipher.evaluate([plaintext, key, nonce], verbosity=False) == ciphertext
