from claasp.ciphers.single_component_ciphers.xor_block_cipher import XorBlockCipher


def test_xor_block_cipher_properties():
    xor = XorBlockCipher(word_bit_size=8, number_of_inputs=2)
    assert xor.type == 'block_cipher'
    assert xor.number_of_rounds == 1
    assert xor.id == 'xor_block_cipher_p8_k8_o8_r1'
    assert xor.component_from(0, 0).id == 'xor_0_0'

    left = xor.evaluate([0x3C, 0xA5])
    right = xor.evaluate([0xA5, 0x3C])
    assert left == right == (0x3C ^ 0xA5)

    xor_three_inputs = XorBlockCipher(word_bit_size=8, number_of_inputs=3)
    assert xor_three_inputs.evaluate([0x12, 0x34, 0x56]) == (0x12 ^ 0x34 ^ 0x56)