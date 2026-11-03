from claasp.ciphers.single_component_ciphers.idea_modmul_cipher import IdeaModmulCipher


def test_idea_modmul_cipher_default_modulus():
    cipher = IdeaModmulCipher(word_bit_size=16, number_of_inputs=2)
    out = cipher.evaluate([0x1234, 2])
    assert cipher.type == "block_cipher"
    assert isinstance(out, int)
    assert 0 <= out < (1 << 16)


def test_idea_modmul_cipher_uses_explicit_modulus():
    cipher = IdeaModmulCipher(word_bit_size=4, number_of_inputs=2, modulus=17)

    assert cipher.evaluate([3, 5]) == 15
