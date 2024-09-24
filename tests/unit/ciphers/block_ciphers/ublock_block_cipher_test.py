from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher

"""
Following are some testing vectors:
1. Ublock 128/128
plaintext = 0x0123456789abcdeffedcba9876543210
key = 0x0123456789abcdeffedcba9876543210
ciphertext = 0x32122bedd023c429023470e1158c147d

2. Ublock 128/256
plaintext = 0x0123456789abcdeffedcba9876543210
key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
ciphertext = 0x64accd6e34cac84d384cd4ba7aeadd19

3. Ublock 256/256
plaintext = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
ciphertext = 0xd8e9351c5f4d27ea842135ca1640ad4b0ce119bc25c03e7c329ea8fe93e7bdfe

Reference: http://www.jcr.cacrnet.org.cn/EN/10.13868/j.cnki.jcr.000334
"""
def test_ublock_block_cipher():
    ublock = UblockBlockCipher()
    assert ublock.type == 'block_cipher'
    assert ublock.family_name == 'ublock'
    assert ublock.number_of_rounds == 16
    assert ublock.id == 'ublock_p128_k128_o128_r16'
    assert ublock.component_from(0, 0).id == 'xor_0_0'

    ublock = UblockBlockCipher(number_of_rounds=4)
    assert ublock.number_of_rounds == 4
    assert ublock.id == 'ublock_p128_k128_o128_r4'
    assert ublock.component_from(3, 0).id == 'xor_3_0'

    ublock = UblockBlockCipher(block_bit_size=128, key_bit_size=128)
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x0123456789abcdeffedcba9876543210
    ciphertext = 0x32122bedd023c429023470e1158c147d
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ublock = UblockBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    ciphertext = 0x64accd6e34cac84d384cd4ba7aeadd19
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ublock = UblockBlockCipher(block_bit_size=256, key_bit_size=256)
    plaintext = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    key = 0x0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f
    ciphertext = 0xd8e9351c5f4d27ea842135ca1640ad4b0ce119bc25c03e7c329ea8fe93e7bdfe
    assert ublock.evaluate([plaintext, key]) == ciphertext
    assert ublock.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
