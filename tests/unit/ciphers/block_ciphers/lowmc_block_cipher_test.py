from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher


def test_lowmc_block_cipher():
    lowmc = LowMCBlockCipher()
    assert lowmc.type == 'block_cipher'
    assert lowmc.family_name == 'lowmc'
    assert lowmc.number_of_rounds == 20
    assert lowmc.id == 'lowmc_p128_k128_o128_r20'
    assert lowmc.component_from(0, 0).id == 'linear_layer_0_0'

    lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4)
    assert lowmc.number_of_rounds == 4
    assert lowmc.id == 'lowmc_p192_k192_o192_r4'
    assert lowmc.component_from(3, 0).id == 'sbox_3_0'

    # Vectorsets for Picnic-L1-20
    lowmc = LowMCBlockCipher(key_bit_size=128)
    key = 0x80000000000000000000000000000000
    plaintext = 0xABFF0000000000000000000000000000
    ciphertext = 0x0E30720B9F64D5C2A7771C8C238D8F70
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0xB5DF537B000000000000000000000000
    plaintext = 0xF77DB57B000000000000000000000000
    ciphertext = 0x0E5961E9992153B13245AF243DD7DDC0
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    # Vectorsets for Picnic-L3-30
    # Very long test
    lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192)
    key = 0x800000000000000000000000000000000000000000000000
    plaintext = 0xABFF00000000000000000000000000000000000000000000
    ciphertext = 0xA85B8244344A2E1B10A17BAB043073F6BB649AE6AF659F6F
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    #
    # Very long test
    key = 0xB5DF537B0000000000000000000000000000000000000000
    plaintext = 0xF77DB57B0000000000000000000000000000000000000000
    ciphertext = 0x210BBC4A434B32DB1E85AE7A27FEE9E41582FAC21D035AA1
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    # Vectorsets for Picnic-L5-38
    # Very long test
    lowmc = LowMCBlockCipher(block_bit_size=256, key_bit_size=256)
    key = 0x8000000000000000000000000000000000000000000000000000000000000000
    plaintext = 0xABFF000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0xB8F20A888A0A9EC4E495F1FB439ABDDE18C1D3D29CF20DF4B10A567AA02C7267
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    #
    # Very long test
    key = 0xF77DB57B00000000000000000000000000000000000000000000000000000000
    plaintext = 0xB5DF537B00000000000000000000000000000000000000000000000000000000
    ciphertext = 0xEEECCE6A584A93306DAEA07519B47AD6402C11DD942AA3166541444977A214C5
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    # Vectorsets for Picnic3-L1-4
    # Note that all values need to be truncated to exact block_bit_size value
    # (129 bits, 136 might raise an error at some point)
    lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129)
    key = 0x8000000000000000000000000000000000 >> 7
    plaintext = 0xabff000000000000000000000000000000 >> 7
    ciphertext = 0x2fd7d5425ee35e667c972f12fb153e9d80 >> 7
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0xab22425149aa612d7fff137220275b1680 >> 7
    plaintext = 0x4b992353a60665bf992d035482c1d27900 >> 7
    ciphertext = 0x2a4062d835c593ea19f822ad242477d280 >> 7
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0xe73af29cfc7ae53e5220d31e2e5917da80 >> 7
    plaintext = 0x304ba7a8de2b5cf887f9a48ab7561bf680 >> 7
    ciphertext = 0x5cd2c355328efde9f378c16123d33fb300 >> 7
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x30f33488532d7eb8a5f8fb4f2e63ba5600 >> 7
    plaintext = 0xc26a5df906158dcb6ac7891da9f49f7800 >> 7
    ciphertext = 0xb43b65f7c535006cf27e86f551bd01580 >> 7
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    # # Vectorsets for Picnic3-L3-4
    lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4)
    key = 0x800000000000000000000000000000000000000000000000
    plaintext = 0xABFF00000000000000000000000000000000000000000000
    ciphertext = 0xf8f7a225de77123129107a20f5543afa7833076653ba2b29
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x81b85dfe40f612275aa3f9199139ebaae8dff8366f2dd34e
    plaintext = 0xb865ccf3fcda8ddbed527dc34dd4150d4a482dcbf7e9643c
    ciphertext = 0x95ef9ed7c37872a7b4602a3fa9c46ebcb84254ed0e44ee9f
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x2405978fdaad9b6d8dcdd18a0c2c0ec68b69dd0a3754fe38
    plaintext = 0x33e8b4552e95ef5279497706bce01ecb4acb860141b7fc43
    ciphertext = 0xddaf0f9d9edd572069a8949faea0d1fd2d91ef262b411caf
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x569d7d822300943d9483477427e88ea227a2e3172c04bcd3
    plaintext = 0xaeeb9d5b61a2a56dd598f7da26dfd78cc992e0aea3fc2e39
    ciphertext = 0x869870ae6547ad0afef27793170d96bc78e040096944808f
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    # # Vectorsets for Picnic3-L5-4
    # # Note that all values need to be truncated to exact block_bit_size value
    # # (255 bits, 256 might raise an error at some point)
    lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4)
    key = 0x8000000000000000000000000000000000000000000000000000000000000000 >> 1
    plaintext = 0xABFF000000000000000000000000000000000000000000000000000000000000 >> 1
    ciphertext = 0xD4721D846DD14DBA3A2C41501C02DA282ECAFD72DF77992F3967EFD6E8F3F356 >> 1
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x7c20be53b6d6008149e19a34b97d9684a0914caf9f7f38b2499811369c3f53da >> 1
    plaintext = 0x8863f129c0387ae5a402a49bd64927c4c65964fb8531b0d761b161b4c97b755e >> 1
    ciphertext = 0x3b6e4b63cc8b08268b6781d5a629d6e03020c1c048d4684161b90ad73339126 >> 1
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0x6df9e78d0fc1b870dabe520514b959636a42304bf43a2408524506c81ea30b14 >> 1
    plaintext = 0x9e5178420520b8cca529595b80c4703b2dcf2a0730643a6f412798605f052b68 >> 1
    ciphertext = 0x0f19fcc8bc18869aab8e4fe81e9767d18cfe715081929f92963b4000000626f8 >> 1
    assert lowmc.evaluate([plaintext, key]) == ciphertext

    key = 0xb071c6d4a377e551254c5dc401a3d08acb99609f418a8c2207f5122b5a17fe9a >> 1
    plaintext = 0xf7616dc514fd0e1028561d098aafa54c34be728cf24a5024df17b9cc2e33fbfa >> 1
    ciphertext = 0x4448c70ac3863021be232c63381687cd5defb50ba28d7b268e19727baebc679a >> 1
    assert lowmc.evaluate([plaintext, key]) == ciphertext
