from claasp.ciphers.block_ciphers.simeck_sbox_block_cipher import SimeckSboxBlockCipher


def test_simeck_sbox_block_cipher():
    simeck = SimeckSboxBlockCipher()
    assert simeck.type == 'block_cipher'
    assert simeck.family_name == 'simeck'
    assert simeck.number_of_rounds == 32
    assert simeck.id == 'simeck_p32_k64_o32_r32'
    assert simeck.component_from(0, 0).id == 'sbox_0_0'

    simeck = SimeckSboxBlockCipher(number_of_rounds=4)
    assert simeck.number_of_rounds == 4
    assert simeck.id == 'simeck_p32_k64_o32_r4'
    assert simeck.component_from(3, 0).id == 'sbox_3_0'

    simeck = SimeckSboxBlockCipher()
    plaintext = 0x65656877
    key = 0x1918111009080100
    ciphertext = 0x770d2c76
    assert simeck.evaluate([plaintext, key]) == ciphertext

    simeck = SimeckSboxBlockCipher(block_bit_size=48, key_bit_size=96)
    plaintext = 0x72696320646e
    key = 0x1a19181211100a0908020100
    ciphertext = 0xf3cf25e33b36
    assert simeck.evaluate([plaintext, key]) == ciphertext

    simeck = SimeckSboxBlockCipher(block_bit_size=64, key_bit_size=128)
    plaintext = 0x656b696c20646e75
    key = 0x1b1a1918131211100b0a090803020100
    ciphertext = 0x45ce69025f7ab7ed
    assert simeck.evaluate([plaintext, key]) == ciphertext
