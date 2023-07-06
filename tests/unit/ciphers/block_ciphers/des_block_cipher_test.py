from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher


def test_des_block_cipher():
    des = DESBlockCipher()
    assert des.type == 'block_cipher'
    assert des.family_name == 'des_block_cipher'
    assert des.number_of_rounds == 16
    assert des.id == 'des_block_cipher_k64_p64_o64_r16'
    assert des.component_from(0, 0).id == 'linear_layer_0_0'

    des = DESBlockCipher(number_of_rounds=4)
    assert des.number_of_rounds == 4
    assert des.id == 'des_block_cipher_k64_p64_o64_r4'
    assert des.component_from(3, 0).id == 'rot_3_0'

    des = DESBlockCipher()
    key = 0x133457799BBCDFF1
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0x85E813540F0AB405
    assert des.evaluate([key, plaintext]) == ciphertext
