from claasp.ciphers.single_component_ciphers.theta_keccak_cipher import ThetaKeccakCipher


def test_theta_keccak_cipher_smoke():
    cipher = ThetaKeccakCipher(bit_size=25)
    out = cipher.evaluate([0])
    assert cipher.type == "permutation"
    assert isinstance(out, int)
