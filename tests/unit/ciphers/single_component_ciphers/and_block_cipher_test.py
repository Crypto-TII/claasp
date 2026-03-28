from claasp.ciphers.single_component_ciphers.and_block_cipher import AndBlockCipher


def test_and_block_cipher_properties():
    and_cipher = AndBlockCipher(word_bit_size=8, number_of_inputs=2)
    assert and_cipher.type == 'block_cipher'
    assert and_cipher.number_of_rounds == 1
    assert and_cipher.id == 'and_block_cipher_p8_k8_o8_r1'
    assert and_cipher.component_from(0, 0).id == 'and_0_0'

    left = and_cipher.evaluate([0x3C, 0xA5])
    right = and_cipher.evaluate([0xA5, 0x3C])
    assert left == right == (0x3C & 0xA5)

    assert and_cipher.evaluate([0xFF, 0x00]) == 0x00

    and_three_inputs = AndBlockCipher(word_bit_size=8, number_of_inputs=3)
    assert and_three_inputs.evaluate([0xF0, 0xCC, 0xAA]) == (0xF0 & 0xCC & 0xAA)