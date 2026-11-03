from claasp.ciphers.single_component_ciphers.reverse_cipher import ReverseCipher


def test_reverse_cipher_involution():
    cipher = ReverseCipher(bit_size=8)
    x = 0b11010010
    assert cipher.type == "permutation"
    assert cipher.evaluate([cipher.evaluate([x])]) == x
