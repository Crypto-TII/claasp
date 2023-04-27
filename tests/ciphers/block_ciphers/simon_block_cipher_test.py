from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher


def test_simon_block_cipher():
    simon = SimonBlockCipher()
    assert simon.type == 'block_cipher'
    assert simon.family_name == 'simon'
    assert simon.number_of_rounds == 32
    assert simon.id == 'simon_p32_k64_o32_r32'
    assert simon.component_from(0, 0).id == 'intermediate_output_0_0'

    simon = SimonBlockCipher(number_of_rounds=4)
    assert simon.number_of_rounds == 4
    assert simon.id == 'simon_p32_k64_o32_r4'
    assert simon.component_from(3, 0).id == 'intermediate_output_3_0'

    simon = SimonBlockCipher()
    plaintext = 0x65656877
    key = 0x1918111009080100
    ciphertext = 0xc69be9bb
    assert simon.evaluate([plaintext, key]) == ciphertext
    assert simon.test_against_reference_code(2) is True

    simon = SimonBlockCipher(block_bit_size=48, key_bit_size=72)
    plaintext = 0x6120676e696c
    key = 0x1211100a0908020100
    ciphertext = 0xdae5ac292cac
    assert simon.evaluate([plaintext, key]) == ciphertext
    assert simon.test_against_reference_code(2) is True

    simon = SimonBlockCipher(block_bit_size=48, key_bit_size=96)
    plaintext = 0x72696320646e
    key = 0x1a19181211100a0908020100
    ciphertext = 0x6e06a5acf156
    assert simon.evaluate([plaintext, key]) == ciphertext
    assert simon.test_against_reference_code(2) is True

    simon = SimonBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0x74206e69206d6f6f6d69732061207369
    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    ciphertext = 0x8d2b5579afc8a3a03bf72a87efe7b868
    assert simon.evaluate([plaintext, key]) == ciphertext
    assert simon.test_against_reference_code(2) is True
