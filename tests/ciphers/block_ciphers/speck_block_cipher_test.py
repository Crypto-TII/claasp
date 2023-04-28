from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_speck_block_cipher():
    speck = SpeckBlockCipher()
    assert speck.type == 'block_cipher'
    assert speck.family_name == 'speck'
    assert speck.number_of_rounds == 22
    assert speck.id == 'speck_p32_k64_o32_r22'
    assert speck.component_from(0, 0).id == 'rot_0_0'

    speck = SpeckBlockCipher(number_of_rounds=4)
    assert speck.number_of_rounds == 4
    assert speck.id == 'speck_p32_k64_o32_r4'
    assert speck.component_from(3, 0).id == 'constant_3_0'

    speck = SpeckBlockCipher()
    plaintext = 0x6574694c
    key = 0x1918111009080100
    ciphertext = 0xa86842f2
    assert speck.evaluate([plaintext, key]) == ciphertext

    speck = SpeckBlockCipher(block_bit_size=64, key_bit_size=96)
    plaintext = 0x74614620736e6165
    key = 0x131211100b0a090803020100
    ciphertext = 0x9f7952ec4175946c
    assert speck.evaluate([plaintext, key]) == ciphertext
