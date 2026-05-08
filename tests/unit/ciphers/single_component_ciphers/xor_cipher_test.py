from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher


def test_xor_cipher_properties():
    cipher = XorCipher(word_bit_size=4, number_of_inputs=3)
    a, b, c = 0b1010, 0b1100, 0b0111
    assert cipher.type == "block_cipher"
    assert cipher.number_of_rounds == 1
    assert cipher.evaluate([a, b, c]) == cipher.evaluate([c, b, a])
