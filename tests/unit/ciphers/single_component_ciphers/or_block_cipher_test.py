from claasp.ciphers.single_component_ciphers.or_block_cipher import OrBlockCipher


def test_or_block_cipher_properties():
    or_cipher = OrBlockCipher(word_bit_size=8, number_of_inputs=2)
    assert or_cipher.type == 'block_cipher'
    assert or_cipher.number_of_rounds == 1
    assert or_cipher.id == 'or_block_cipher_p8_k8_o8_r1'
    assert or_cipher.component_from(0, 0).id == 'or_0_0'

    left = or_cipher.evaluate([0x3C, 0xA5])
    right = or_cipher.evaluate([0xA5, 0x3C])
    assert left == right == (0x3C | 0xA5)

    assert or_cipher.evaluate([0x00, 0xA5]) == 0xA5

    or_three_inputs = OrBlockCipher(word_bit_size=8, number_of_inputs=3)
    assert or_three_inputs.evaluate([0x12, 0x34, 0x56]) == (0x12 | 0x34 | 0x56)