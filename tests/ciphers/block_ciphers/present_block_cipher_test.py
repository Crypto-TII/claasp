from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher


def test_present_block_cipher():
    present = PresentBlockCipher()
    assert present.type == 'block_cipher'
    assert present.family_name == 'present'
    assert present.number_of_rounds == 31
    assert present.id == 'present_p64_k80_o64_r31'
    assert present.component_from(0, 0).id == 'xor_0_0'

    present = PresentBlockCipher(number_of_rounds=4)
    assert present.number_of_rounds == 4
    assert present.id == 'present_p64_k80_o64_r4'
    assert present.component_from(3, 0).id == 'xor_3_0'

    present = PresentBlockCipher()
    plaintext = 0x42c20fd3b586879e
    key = 0x98edeafc899338c45fad
    ciphertext = 0xa1e546ae14c26565
    assert present.evaluate([plaintext, key]) == ciphertext
    assert present.test_against_reference_code(2) is True

    present = PresentBlockCipher(key_bit_size=128)
    plaintext = 0x42c20fd3b586879e
    key = 0x687ded3b3c85b3f35b1009863e2a8cbf
    ciphertext = 0x82f5b82cb02cd1b6
    assert present.evaluate([plaintext, key]) == ciphertext
    assert present.test_against_reference_code(2) is True
