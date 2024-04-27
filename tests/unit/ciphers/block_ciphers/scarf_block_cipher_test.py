from claasp.ciphers.block_ciphers.scarf_block_cipher import SCARFBlockCipher


def test_scarf_block_cipher():
    cipher = SCARFBlockCipher()
    assert cipher.type == 'block_cipher'
    assert cipher.family_name == 'scarf'
    assert cipher.number_of_rounds == 8
    assert cipher.id == 'scarf_p10_k240_i48_o10_r8'
    assert cipher.component_from(0, 0).id == 'constant_0_0'

    plaintext = 0x0
    key = 0xEBA347BD715B4AE6E8BAE2BE82C35714014D1726D82676E50618AA168941
    tweak = 0x71249C3CAAB0
    ciphertext = 0xBD
    assert cipher.evaluate([plaintext, key, tweak]) == ciphertext

    plaintext = 0x3FF
    ciphertext = 0x145
    assert cipher.evaluate([plaintext, key, tweak]) == ciphertext
    assert cipher.evaluate_vectorized([plaintext, key, tweak], evaluate_api = True) == ciphertext