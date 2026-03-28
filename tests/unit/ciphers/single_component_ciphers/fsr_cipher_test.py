from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher


def test_fsr_cipher_smoke():
    cipher = FsrCipher(register_size=4)
    out = cipher.evaluate([0b1010])
    assert cipher.type == "hash_function"
    assert isinstance(out, int)
