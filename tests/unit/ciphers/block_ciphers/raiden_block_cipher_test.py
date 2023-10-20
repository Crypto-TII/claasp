from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher


def test_raiden_block_cipher():
    raiden = RaidenBlockCipher()
    assert raiden.type == 'block_cipher'
    assert raiden.family_name == 'raiden'
    assert raiden.number_of_rounds == 16
    assert raiden.id == 'raiden_p64_k128_o64_r16'
    assert raiden.component_from(0, 0).id == 'modadd_0_0'

    raiden = RaidenBlockCipher(number_of_rounds=4)
    assert raiden.number_of_rounds == 4
    assert raiden.id == 'raiden_p64_k128_o64_r4'
    assert raiden.component_from(3, 0).id == 'modadd_3_0'

    raiden = RaidenBlockCipher()
    plaintext = 0xbd7d764dff0ada1e
    key = 0x1de1c3c2c65880074c32dce537b22ab3
    ciphertext = 0x99bf13c039b49812
    assert raiden.evaluate([plaintext, key]) == ciphertext
    assert raiden.test_against_reference_code(2) is True

    raiden = RaidenBlockCipher(32, 64, 32)
    plaintext = 0xb779ee0a
    key = 0x0e2ddd5c5b4ca9d4
    ciphertext = 0x5a1674df
    assert raiden.evaluate([plaintext, key]) == ciphertext
    assert raiden.test_against_reference_code(2) is True
