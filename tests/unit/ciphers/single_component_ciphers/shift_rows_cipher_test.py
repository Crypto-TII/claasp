from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher


def test_shift_rows_cipher_smoke():
    cipher = ShiftRowsCipher(bit_size=16, parameter=4)
    out = cipher.evaluate([0x1234])
    assert cipher.type == "permutation"
    assert isinstance(out, int)
