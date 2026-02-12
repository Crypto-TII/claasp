from claasp.ciphers.permutations.chacha_permutation import ROUND_MODE_HALF, ROUND_MODE_SINGLE
from claasp.ciphers.stream_ciphers.chacha_stream_cipher import ChachaStreamCipher


def test_chacha_stream_cipher():
    chacha = ChachaStreamCipher()
    assert chacha.family_name == 'chacha_stream_cipher'
    assert chacha.type == 'stream_cipher'
    assert chacha.number_of_rounds == 40
    assert chacha.id == 'chacha_stream_cipher_p512_k256_n96_o512_r40'
    assert chacha.component_from(0, 0).id == 'modadd_0_0'

    chacha = ChachaStreamCipher(number_of_rounds=4, round_mode=ROUND_MODE_HALF)
    assert chacha.number_of_rounds == 4
    assert chacha.id == 'chacha_stream_cipher_p512_k256_n96_o512_r4'
    assert chacha.component_from(3, 0).id == 'modadd_3_0'

    cipher = ChachaStreamCipher(number_of_rounds=20, round_mode=ROUND_MODE_SINGLE)
    plaintext = 0x61707865_3320646e_79622d32_6b206574_03020100_07060504_0b0a0908_0f0e0d0c_13121110_17161514_1b1a1918_1f1e1d1c_00000001_09000000_4a000000_00000000
    key = 0x00010203_04050607_08090a0b_0c0d0e0f_10111213_14151617_18191a1b_1c1d1e1f
    nonce = 0x00000000_00000009_0000004a_00000000
    ciphertext = 0xe4e7f110_15593bd1_1fdd0f50_c47120a3_c7f4d1c7_0368c033_9aaa2204_4e6cd4c3_466482d2_09aa9f07_05d7c214_a2028bd9_d19c12b5_b94e16de_e883d0cb_4e3c50a2
    assert cipher.evaluate([plaintext, key, nonce], verbosity=False) == ciphertext
