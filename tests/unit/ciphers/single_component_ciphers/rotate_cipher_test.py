from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher


def test_rotate_cipher_inverse_parameters():
    right = RotateCipher(bit_size=8, parameter=2)
    left = RotateCipher(bit_size=8, parameter=-2)
    x = 0xA5
    assert right.type == "permutation"
    assert left.evaluate([right.evaluate([x])]) == x
