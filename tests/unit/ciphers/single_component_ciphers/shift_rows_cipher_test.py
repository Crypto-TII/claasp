from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher


def test_shift_rows_cipher_smoke():
    cipher = ShiftRowsCipher(word_bit_size=8, rotation_amount=1, number_of_words=4)
    out = cipher.evaluate([0x12345678])
    assert cipher.type == "permutation"
    assert isinstance(out, int)
