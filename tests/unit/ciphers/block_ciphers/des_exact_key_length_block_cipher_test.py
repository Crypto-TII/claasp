from claasp.ciphers.block_ciphers.des_exact_key_length_block_cipher import DESExactKeyLengthBlockCipher


def test_des_exact_key_length_block_cipher():
    des_exact_key = DESExactKeyLengthBlockCipher()
    assert des_exact_key.type == 'block_cipher'
    assert des_exact_key.family_name == 'des_exact_key_length_block_cipher'
    assert des_exact_key.number_of_rounds == 16
    assert des_exact_key.id == 'des_exact_key_length_block_cipher_k56_p64_o64_r16'
    assert des_exact_key.component_from(0, 0).id == 'linear_layer_0_0'

    des_exact_key = DESExactKeyLengthBlockCipher(number_of_rounds=4)
    assert des_exact_key.number_of_rounds == 4
    assert des_exact_key.id == 'des_exact_key_length_block_cipher_k56_p64_o64_r4'
    assert des_exact_key.component_from(3, 0).id == 'rot_3_0'

    des_cipher = DESExactKeyLengthBlockCipher()
    key = 0x12695BC9B7B7F8
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0x85E813540F0AB405
    assert des_cipher.evaluate([key, plaintext]) == ciphertext
