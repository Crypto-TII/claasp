from claasp.ciphers.block_ciphers.speedy_block_cipher import SpeedyBlockCipher


def test_speedy_block_cipher():
    """
    Pytests for SPEEDY cipher

    Test vectors used are those reported in [LMM+2021]_.
    """
    speedy = SpeedyBlockCipher(number_of_rounds=5)
    assert speedy.type == 'block_cipher'
    assert speedy.family_name == 'speedy'
    assert speedy.number_of_rounds == 5
    assert speedy.id == 'speedy_p192_k192_o192_r5'
    assert speedy.component_from(0, 5).id == 'sbox_0_5'
    plaintext = 0xa13a632451070e4382a27f26a40682f3fe9ff68028d24fdb
    key = 0x764c4f6254e1bff208e95862428faed01584f4207a7e8477
    ciphertext = 0x01da25a93d1cfc5e4c0b74f677eb746c281a260193b7755a
    assert speedy.evaluate([plaintext, key]) == ciphertext

    speedy = SpeedyBlockCipher(number_of_rounds=6)
    assert speedy.number_of_rounds == 6
    assert speedy.id == 'speedy_p192_k192_o192_r6'
    assert speedy.component_from(1, 6).id == 'sbox_1_6'
    plaintext = 0xa13a632451070e4382a27f26a40682f3fe9ff68028d24fdb
    key = 0x764c4f6254e1bff208e95862428faed01584f4207a7e8477
    ciphertext = 0x88bfd3dc140f38bc53a66687f5307860560ebec41100662d
    assert speedy.evaluate([plaintext, key]) == ciphertext

    speedy = SpeedyBlockCipher(number_of_rounds=7)
    assert speedy.number_of_rounds == 7
    assert speedy.id == 'speedy_p192_k192_o192_r7'
    assert speedy.component_from(2, 7).id == 'sbox_2_7'
    plaintext = 0xa13a632451070e4382a27f26a40682f3fe9ff68028d24fdb
    key = 0x764c4f6254e1bff208e95862428faed01584f4207a7e8477
    ciphertext = 0xed3d0ea11c427bd32570df41c6fd66ebbf4916e760ed0943
    assert speedy.evaluate([plaintext, key]) == ciphertext
