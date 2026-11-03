from claasp.ciphers.single_component_ciphers.theta_xoodoo_cipher import ThetaXoodooCipher


def test_theta_xoodoo_cipher_smoke():
    cipher = ThetaXoodooCipher(bit_size=384)
    out = cipher.evaluate([0])
    assert cipher.type == "permutation"
    assert isinstance(out, int)
