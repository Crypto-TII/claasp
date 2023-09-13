from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher


def test_xtea_block_cipher():
    xtea = XTeaBlockCipher()
    assert xtea.type == 'block_cipher'
    assert xtea.family_name == 'xtea'
    assert xtea.number_of_rounds == 32
    assert xtea.id == 'xtea_p64_k128_o64_r32'
    assert xtea.component_from(0, 0).id == 'shift_0_0'

    xtea = XTeaBlockCipher(number_of_rounds=4)
    assert xtea.number_of_rounds == 4
    assert xtea.id == 'xtea_p64_k128_o64_r4'
    assert xtea.component_from(3, 0).id == 'shift_3_0'

    xtea = XTeaBlockCipher()
    plaintext = 0xbd7d764dff0ada1e
    key = 0x1de1c3c2c65880074c32dce537b22ab3
    ciphertext = 0x91c0fec24d17fe49
    assert xtea.evaluate([plaintext, key]) == ciphertext
    assert xtea.test_against_reference_code(2) is True

    xtea = XTeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=32)
    plaintext = 0xb779ee0a
    key = 0x0e2ddd5c5b4ca9d4
    ciphertext = 0x5be9022a
    assert xtea.evaluate([plaintext, key]) == ciphertext
    assert xtea.test_against_reference_code(2) is True
