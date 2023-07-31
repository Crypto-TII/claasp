from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher


def test_tea_block_cipher():
    tea = TeaBlockCipher()
    assert tea.type == 'block_cipher'
    assert tea.family_name == 'tea'
    assert tea.number_of_rounds == 32
    assert tea.id == 'tea_p64_k128_o64_r32'
    assert tea.component_from(0, 0).id == 'shift_0_0'

    tea = TeaBlockCipher(number_of_rounds=4)
    assert tea.number_of_rounds == 4
    assert tea.id == 'tea_p64_k128_o64_r4'
    assert tea.component_from(3, 0).id == 'shift_3_0'

    tea = TeaBlockCipher()
    plaintext = 0xbd7d764dff0ada1e
    key = 0x1de1c3c2c65880074c32dce537b22ab3
    ciphertext = 0x5e89b6140012c6da
    assert tea.evaluate([plaintext, key]) == ciphertext
    assert tea.test_against_reference_code(2) is True

    tea = TeaBlockCipher(32, 64, 32)
    plaintext = 0xb779ee0a
    key = 0x0e2ddd5c5b4ca9d4
    ciphertext = 0x25476362
    assert tea.evaluate([plaintext, key]) == ciphertext
    assert tea.test_against_reference_code(2) is True
