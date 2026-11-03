from claasp.ciphers.single_component_ciphers.theta_gaston_cipher import ThetaGastonCipher


def test_theta_gaston_cipher_smoke():
    cipher = ThetaGastonCipher(bit_size=320, rotation_amounts_parameter=[1, 18, 23, 25, 32, 52, 60, 63])
    out = cipher.evaluate([0])
    assert cipher.type == "hash_function"
    assert isinstance(out, int)


def test_theta_gaston_cipher_default_rotation_amounts():
    cipher = ThetaGastonCipher()

    assert cipher.family_name == "theta_gaston_cipher"
    assert cipher.number_of_rounds == 1
