from claasp.ciphers.block_ciphers.lowmc_block_cipher import LowMCBlockCipher


def test_lowmc_block_cipher():
    # Vectorsets for Picnic-L1-20
    lowmc = LowMCBlockCipher(key_bit_size=128, number_of_rounds=4, number_of_sboxes=10)
    assert lowmc.type == 'block_cipher'
    assert lowmc.family_name == 'lowmc'
    assert lowmc.number_of_rounds == 4
    assert lowmc.id == 'lowmc_p128_k128_o128_r4'
    assert lowmc.component_from(0, 0).id == 'linear_layer_0_0'

    key = 0x80000000000000000000000000000000
    plaintext = 0xABFF0000000000000000000000000000
    ciphertext = 0XCAE1713F0BD2A6362F9F0ACC49976A02
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    # Vectorsets for Picnic-L3-30
    lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4)
    assert lowmc.number_of_rounds == 4
    assert lowmc.id == 'lowmc_p192_k192_o192_r4'
    assert lowmc.component_from(3, 0).id == 'sbox_3_0'

    key = 0x800000000000000000000000000000000000000000000000
    plaintext = 0xABFF00000000000000000000000000000000000000000000
    ciphertext = 0XF8F7A225DE77123129107A20F5543AFA7833076653BA2B29
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext


    # Vectorsets for Picnic-L5-38
    lowmc = LowMCBlockCipher(block_bit_size=256, key_bit_size=256, number_of_rounds=4, number_of_sboxes=10)
    key = 0x8000000000000000000000000000000000000000000000000000000000000000
    plaintext = 0xABFF000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0X8E416601CC582CE3A114ECBD6C2F669B2974F9F56C3FE1129FA525081CC9F8C0
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext



    # Vectorsets for Picnic3-L1-4
    # Note that all values need to be truncated to exact block_bit_size value
    # (129 bits, 136 might raise an error at some point)
    lowmc = LowMCBlockCipher(block_bit_size=129, key_bit_size=129)
    key = 0x30f33488532d7eb8a5f8fb4f2e63ba5600 >> 7
    plaintext = 0xc26a5df906158dcb6ac7891da9f49f7800 >> 7
    ciphertext = 0xb43b65f7c535006cf27e86f551bd01580 >> 7
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext


    # Vectorsets for Picnic3-L3-4
    lowmc = LowMCBlockCipher(block_bit_size=192, key_bit_size=192, number_of_rounds=4)
    key = 0x569d7d822300943d9483477427e88ea227a2e3172c04bcd3
    plaintext = 0xaeeb9d5b61a2a56dd598f7da26dfd78cc992e0aea3fc2e39
    ciphertext = 0x869870ae6547ad0afef27793170d96bc78e040096944808f
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext


    # Vectorsets for Picnic3-L5-4
    # Note that all values need to be truncated to exact block_bit_size value
    # (255 bits, 256 might raise an error at some point)
    lowmc = LowMCBlockCipher(block_bit_size=255, key_bit_size=255, number_of_rounds=4)
    key = 0xb071c6d4a377e551254c5dc401a3d08acb99609f418a8c2207f5122b5a17fe9a >> 1
    plaintext = 0xf7616dc514fd0e1028561d098aafa54c34be728cf24a5024df17b9cc2e33fbfa >> 1
    ciphertext = 0x4448c70ac3863021be232c63381687cd5defb50ba28d7b268e19727baebc679a >> 1
    assert lowmc.evaluate([plaintext, key]) == ciphertext
    assert lowmc.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
