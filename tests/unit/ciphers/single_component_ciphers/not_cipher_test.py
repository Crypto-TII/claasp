from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher


def test_not_cipher_involution():
    cipher = NotCipher(bit_size=8)
    x = 0xA5
    assert cipher.type == "permutation"
    assert cipher.evaluate([cipher.evaluate([x])]) == x
