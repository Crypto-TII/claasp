from claasp.ciphers.single_component_ciphers.idea_modmul_block_cipher import IdeaModmulBlockCipher


def test_idea_modmul_block_cipher_properties():
    idea_modmul = IdeaModmulBlockCipher(word_bit_size=16, number_of_inputs=2, modulus=65537)
    assert idea_modmul.type == 'block_cipher'
    assert idea_modmul.id == 'idea_modmul_block_cipher_p16_k16_o16_r1'
    assert idea_modmul.component_from(0, 0).id == 'idea_modmul_0_0'

    assert idea_modmul.evaluate([0x0001, 0x0002]) == 0x0002