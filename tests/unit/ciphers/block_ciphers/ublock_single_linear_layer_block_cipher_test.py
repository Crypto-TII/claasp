from claasp.ciphers.block_ciphers.ublock_single_linear_layer_block_cipher import UblockSingleLinearLayerBlockCipher


def test_ublock_single_linear_layer_block_cipher():
    ublock = UblockSingleLinearLayerBlockCipher()
    assert ublock.type == "block_cipher"
    assert ublock.family_name == "ublock"
    assert ublock.number_of_rounds == 16
    assert ublock.id == "ublock_p128_k128_o128_r16"
    assert ublock.component_from(0, 0).id == "xor_0_0"

    ublock = UblockSingleLinearLayerBlockCipher(number_of_rounds=4)
    assert ublock.number_of_rounds == 4
    assert ublock.id == "ublock_p128_k128_o128_r4"
    assert ublock.component_from(3, 0).id == "xor_3_0"

    # Reference: http://www.jcr.cacrnet.org.cn/EN/10.13868/j.cnki.jcr.000334
    ublock = UblockSingleLinearLayerBlockCipher(block_bit_size=128, key_bit_size=128)
    plaintext = 0x0123456789ABCDEFFEDCBA9876543210
    key = 0x0123456789ABCDEFFEDCBA9876543210
    ciphertext = 0x32122BEDD023C429023470E1158C147D
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ublock = UblockSingleLinearLayerBlockCipher(block_bit_size=128, key_bit_size=256, number_of_rounds=24)
    plaintext = 0x0123456789ABCDEFFEDCBA9876543210
    key = 0x0123456789ABCDEFFEDCBA9876543210000102030405060708090A0B0C0D0E0F
    ciphertext = 0x64ACCD6E34CAC84D384CD4BA7AEADD19
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ublock = UblockSingleLinearLayerBlockCipher(block_bit_size=256, key_bit_size=256, number_of_rounds=24)
    plaintext = 0x0123456789ABCDEFFEDCBA9876543210000102030405060708090A0B0C0D0E0F
    key = 0x0123456789ABCDEFFEDCBA9876543210000102030405060708090A0B0C0D0E0F
    ciphertext = 0xD8E9351C5F4D27EA842135CA1640AD4B0CE119BC25C03E7C329EA8FE93E7BDFE
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
