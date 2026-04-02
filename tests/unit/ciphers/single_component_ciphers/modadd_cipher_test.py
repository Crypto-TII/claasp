from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher


def test_modadd_cipher_properties():
    cipher = ModaddCipher(word_bit_size=4, number_of_inputs=3)
    a, b, c = 11, 7, 3
    assert cipher.type == "block_cipher"
    assert cipher.evaluate([a, b, c]) == cipher.evaluate([c, b, a])
