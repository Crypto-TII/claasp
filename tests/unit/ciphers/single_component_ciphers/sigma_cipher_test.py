from claasp.ciphers.single_component_ciphers.sigma_cipher import SigmaCipher


def test_sigma_cipher_smoke():
    cipher = SigmaCipher(bit_size=8, rotation_amounts_parameter=[1, 2])
    out = cipher.evaluate([0xA5])
    assert cipher.type == "hash_function"
    assert isinstance(out, int)


def test_sigma_cipher_default_rotation_amounts():
    cipher = SigmaCipher(bit_size=8)

    assert cipher.evaluate([0xA5]) == (0xA5 ^ 0xD2 ^ 0x69)
