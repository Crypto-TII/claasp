from claasp.ciphers.single_component_ciphers.modsub_block_cipher import ModsubBlockCipher


def test_modsub_block_cipher_properties():
    modsub = ModsubBlockCipher(word_bit_size=8, number_of_inputs=2, modulus=256)
    assert modsub.type == 'block_cipher'
    assert modsub.id == 'modsub_block_cipher_p8_k8_o8_r1'
    assert modsub.component_from(0, 0).id == 'modsub_0_0'

    assert modsub.evaluate([0x03, 0x05]) == ((0x03 - 0x05) % 256)