from claasp.ciphers.block_ciphers.sparx_block_cipher import SparxBlockCipher


def test_sparx_block_cipher():
    sparx = SparxBlockCipher()
    assert sparx.type == 'block_cipher'
    assert sparx.family_name == 'sparx'
    assert sparx.number_of_rounds == 8
    assert sparx.id == 'sparx_p64_k128_o64_r8'
    assert sparx.component_from(0, 0).id == 'xor_0_0'

    sparx = SparxBlockCipher(number_of_rounds=4)
    assert sparx.number_of_rounds == 4
    assert sparx.id == 'sparx_p64_k128_o64_r4'
    assert sparx.component_from(3, 0).id == 'xor_3_0'

    sparx = SparxBlockCipher()
    plaintext = 0x0123456789abcdef
    key = 0x00112233445566778899aabbccddeeff
    ciphertext = 0x2bbef15201f55f98
    assert sparx.evaluate([plaintext, key]) == ciphertext
    assert sparx.test_against_reference_code(2) is True

    sparx = SparxBlockCipher(block_bit_size=128)
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x00112233445566778899aabbccddeeff
    ciphertext = 0x1cee75407dbf23d8e0ee1597f42852d8
    assert sparx.evaluate([plaintext, key]) == ciphertext
    assert sparx.test_against_reference_code(2) is True

    sparx = SparxBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0x0123456789abcdeffedcba9876543210
    key = 0x00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100
    ciphertext = 0x3328e63714c76ce632d15a54e4b0c820
    assert sparx.evaluate([plaintext, key]) == ciphertext
    assert sparx.test_against_reference_code(2) is True
