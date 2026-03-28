from claasp.ciphers.single_component_ciphers.modmul_block_cipher import ModmulBlockCipher


def test_modmul_block_cipher_properties():
    modmul = ModmulBlockCipher(word_bit_size=8, number_of_inputs=2, modulus=256)
    assert modmul.type == 'block_cipher'
    assert modmul.id == 'modmul_block_cipher_p8_k8_o8_r1'
    assert modmul.component_from(0, 0).id == 'modmul_0_0'

    assert modmul.evaluate([0x0F, 0x03]) == ((0x0F * 0x03) % 256)
