from claasp.ciphers.single_component_ciphers.modsub_cipher import ModsubCipher


def test_modsub_cipher_non_commutative():
    cipher = ModsubCipher(word_bit_size=4, number_of_inputs=2)
    a, b = 11, 7
    assert cipher.type == "block_cipher"
    assert cipher.evaluate([a, b]) != cipher.evaluate([b, a])
