from claasp.ciphers.single_component_ciphers.modadd_block_cipher import ModaddBlockCipher


def test_modadd_block_cipher_properties():
    modadd = ModaddBlockCipher(word_bit_size=8, number_of_inputs=2, modulus=256)
    assert modadd.type == 'block_cipher'
    assert modadd.id == 'modadd_block_cipher_p8_k8_o8_r1'
    assert modadd.component_from(0, 0).id == 'modadd_0_0'

    assert modadd.evaluate([0xFE, 0x05]) == ((0xFE + 0x05) % 256)

    modadd_three_inputs = ModaddBlockCipher(word_bit_size=8, number_of_inputs=3, modulus=256)
    assert modadd_three_inputs.evaluate([0x12, 0x34, 0x56]) == ((0x12 + 0x34 + 0x56) % 256)
