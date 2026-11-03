from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
from claasp.ciphers.block_ciphers.simeck_sbox_block_cipher import SimeckSboxBlockCipher


def test_simeck_sbox_block_cipher():
    simeck = SimeckSboxBlockCipher()
    assert simeck.type == 'block_cipher'
    assert simeck.family_name == 'simeck_sbox'
    assert simeck.number_of_rounds == 32
    assert simeck.id == 'simeck_sbox_p32_k64_o32_r32'
    assert simeck.component_from(0, 0).id == 'sbox_0_0'

    simeck = SimeckSboxBlockCipher(number_of_rounds=4)
    assert simeck.number_of_rounds == 4
    assert simeck.id == 'simeck_sbox_p32_k64_o32_r4'
    assert simeck.component_from(3, 0).id == 'sbox_3_0'

    simeck = SimeckSboxBlockCipher()
    plaintext = 0x65656877
    key = 0x1918111009080100
    ciphertext = 0x770d2c76
    assert simeck.evaluate([plaintext, key]) == ciphertext

    simeck = SimeckSboxBlockCipher(block_bit_size=48, key_bit_size=96)
    plaintext = 0x72696320646e
    key = 0x1a19181211100a0908020100
    ciphertext = 0xf3cf25e33b36
    assert simeck.evaluate([plaintext, key]) == ciphertext

    simeck = SimeckSboxBlockCipher(block_bit_size=64, key_bit_size=128)
    plaintext = 0x656b696c20646e75
    key = 0x1b1a1918131211100b0a090803020100
    ciphertext = 0x45ce69025f7ab7ed
    assert simeck.evaluate([plaintext, key]) == ciphertext


def test_simeck_sbox_block_cipher_matches_bitwise_implementation():
    """
    Regression test guarding against divergences between the two independent
    implementations of the Simeck round function: the direct bitwise formula
    (SimeckBlockCipher, using AND/XOR/ROTATE components) and the SBOX-table
    lookup (SimeckSboxBlockCipher).

    This specifically covers the case that slipped past the hardcoded official
    test vectors below: SimeckBlockCipher.feistel_function used to hardcode
    `list(range(self.word_size))` as the bit-position list for its AND
    component's *raw* operand, instead of using that operand's actual bit
    positions. This is harmless when `feistel_function` is applied to the
    plaintext halves (whose bit positions always happen to already be
    `range(0, word_size)`), but wrong when it is applied to a key word with a
    non-zero offset inside the key schedule (`update_keys_buffer`), which is
    exactly the case for two of the four key words every round. That bug only
    changes the computed round keys -- and hence the ciphertext -- for keys
    where the substituted (wrong) word and the correct one differ in at least
    one of the bit positions that matter; the official test vectors above
    happen to not be such a key, which is why they kept passing. Cross-checking
    against SimeckSboxBlockCipher (whose SBOX-table construction has always
    correctly tracked each operand's own bit positions) on a handful of
    additional fixed plaintext/key pairs -- distinct from the official vectors
    above -- catches this class of regression.
    """
    configs_and_inputs = [
        (32, 64, 32, (0x00000000, 0x0000000000000000)),
        (32, 64, 32, (0xffffffff, 0xffffffffffffffff)),
        (32, 64, 32, (0xc8065964, 0x147f2e18adc67c94)),
        (32, 64, 32, (0xe57e02d0, 0x915a7f79df5bab03)),
        (48, 96, 36, (0x262f3020f69d, 0x92290d1af986cda743bbc371)),
        (48, 96, 36, (0xb3bc0d9af26d, 0x65e6cc5740f2cfeac787a322)),
        (64, 128, 44, (0xe512ac9c775b8a02, 0x5e3e91a8be951694eff6c534b240dea1)),
        (64, 128, 44, (0xa9413fbe21346957, 0x03c28f7c7706ff547fe9d21ea74c2ba7)),
    ]
    for block_bit_size, key_bit_size, number_of_rounds, (plaintext, key) in configs_and_inputs:
        bitwise = SimeckBlockCipher(
            block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=number_of_rounds
        )
        sbox = SimeckSboxBlockCipher(
            block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=number_of_rounds
        )
        assert bitwise.evaluate([plaintext, key]) == sbox.evaluate([plaintext, key])
