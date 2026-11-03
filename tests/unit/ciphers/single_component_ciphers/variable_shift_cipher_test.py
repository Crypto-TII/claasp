from claasp.ciphers.single_component_ciphers.variable_shift_cipher import VariableShiftCipher


def test_variable_shift_cipher_zero_amount():
    cipher = VariableShiftCipher(bit_size=8, amount_bit_size=3, direction=1)
    x = 0xA5
    assert cipher.type == "hash_function"
    assert cipher.evaluate([x, 0]) == x
