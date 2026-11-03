from claasp.ciphers.single_component_ciphers.linear_layer_cipher import LinearLayerCipher


def test_linear_layer_cipher_identity_matrix():
    cipher = LinearLayerCipher(bit_size=4)
    assert cipher.type == "permutation"
    assert cipher.evaluate([0b1010]) == 0b1010
