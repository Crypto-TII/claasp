from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher


def test_lea_block_cipher():
    lea = LeaBlockCipher()
    assert lea.type == 'block_cipher'
    assert lea.family_name == 'lea'
    assert lea.number_of_rounds == 28
    assert lea.id == 'lea_p128_k192_o128_r28'
    assert lea.component_from(0, 0).id == 'constant_0_0'

    lea = LeaBlockCipher(number_of_rounds=4)
    assert lea.number_of_rounds == 4
    assert lea.id == 'lea_p128_k192_o128_r4'
    assert lea.component_from(3, 0).id == 'constant_3_0'

    lea = LeaBlockCipher(block_bit_size=128, key_bit_size=128)
    plaintext = 0x101112131415161718191a1b1c1d1e1f
    key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0
    assert lea.evaluate([plaintext, key], verbosity=False) == 0x9fc84e3528c6c6185532c7a704648bfd

    lea = LeaBlockCipher(block_bit_size=128, key_bit_size=192)
    plaintext = 0x202122232425262728292a2b2c2d2e2f
    key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687
    assert lea.evaluate([plaintext, key]) == 0x6fb95e325aad1b878cdcf5357674c6f2

    lea = LeaBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0x303132333435363738393a3b3c3d3e3f
    key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f
    assert lea.evaluate([plaintext, key]) == 0xd651aff647b189c13a8900ca27f9e197
