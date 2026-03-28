from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher


def test_shift_cipher_hash_type():
    cipher = ShiftCipher(bit_size=8, parameter=1)
    assert cipher.type == "hash_function"
    assert cipher.evaluate([0b10000001]) != 0b10000001
