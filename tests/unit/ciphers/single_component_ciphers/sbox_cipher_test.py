from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher


def test_sbox_cipher_identity_table_default():
    cipher = SboxCipher(bit_size=4)
    assert cipher.type == "hash_function"
    assert cipher.evaluate([0b1010]) == 0b1010
