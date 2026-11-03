from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher


def test_constant_cipher_value():
    cipher = ConstantCipher(output_bit_size=8, value=0x5A)
    assert cipher.type == "hash_function"
    assert cipher.evaluate([]) == 0x5A
