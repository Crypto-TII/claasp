from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher


def test_simeck_block_cipher():
    simeck = SimeckBlockCipher()
    assert simeck.type == 'block_cipher'
    assert simeck.family_name == 'simeck'
    assert simeck.number_of_rounds == 32
    assert simeck.id == 'simeck_p32_k64_o32_r32'
    assert simeck.component_from(0, 0).id == 'rot_0_0'

    simeck = SimeckBlockCipher(number_of_rounds=4)
    assert simeck.number_of_rounds == 4
    assert simeck.id == 'simeck_p32_k64_o32_r4'
    assert simeck.component_from(3, 0).id == 'rot_3_0'

    simeck = SimeckBlockCipher()
    plaintext = 0x65656877
    key = 0x1918111009080100
    ciphertext = 0x770d2c76
    assert simeck.evaluate([plaintext, key]) == ciphertext

    simeck = SimeckBlockCipher(block_bit_size=48, key_bit_size=96)
    plaintext = 0x72696320646e
    key = 0x1a19181211100a0908020100
    ciphertext = 0xf3cf25e33b36
    assert simeck.evaluate([plaintext, key]) == ciphertext
