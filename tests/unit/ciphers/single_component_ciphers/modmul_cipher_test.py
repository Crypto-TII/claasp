from claasp.ciphers.single_component_ciphers.modmul_cipher import ModmulCipher


def test_modmul_cipher_commutative():
    cipher = ModmulCipher(word_bit_size=8, number_of_inputs=2)
    a, b = 13, 19
    assert cipher.type == "block_cipher"
    assert cipher.evaluate([a, b]) == cipher.evaluate([b, a])
