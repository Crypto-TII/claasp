from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.simon_sbox_block_cipher import SimonSboxBlockCipher


def test_simon_sbox_block_cipher():
    simon = SimonSboxBlockCipher()
    assert simon.type == 'block_cipher'
    assert simon.family_name == 'simon_sbox'
    assert simon.number_of_rounds == 32
    assert simon.id == 'simon_sbox_p32_k64_o32_r32'
    assert simon.component_from(0, 0).id == 'intermediate_output_0_0'

    simon = SimonSboxBlockCipher(number_of_rounds=4)
    assert simon.number_of_rounds == 4
    assert simon.id == 'simon_sbox_p32_k64_o32_r4'
    assert simon.component_from(3, 0).id == 'intermediate_output_3_0'

    simon = SimonSboxBlockCipher()
    plaintext = 0x65656877
    key = 0x1918111009080100
    ciphertext = 0xc69be9bb
    assert simon.evaluate([plaintext, key]) == ciphertext


    simon = SimonSboxBlockCipher(block_bit_size=48, key_bit_size=72)
    plaintext = 0x6120676e696c
    key = 0x1211100a0908020100
    ciphertext = 0xdae5ac292cac
    assert simon.evaluate([plaintext, key]) == ciphertext


    simon = SimonSboxBlockCipher(block_bit_size=48, key_bit_size=96)
    plaintext = 0x72696320646e
    key = 0x1a19181211100a0908020100
    ciphertext = 0x6e06a5acf156
    assert simon.evaluate([plaintext, key]) == ciphertext


    simon = SimonSboxBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0x74206e69206d6f6f6d69732061207369
    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    ciphertext = 0x8d2b5579afc8a3a03bf72a87efe7b868
    assert simon.evaluate([plaintext, key]) == ciphertext


def test_simon_sbox_block_cipher_matches_bitwise_implementation():
    """
    Regression test guarding against divergences between the two independent
    implementations of the Simon round function: the direct bitwise formula
    (SimonBlockCipher, using AND/XOR/ROTATE components) and the SBOX-table
    lookup (SimonSboxBlockCipher, whose SBOX is a 512-entry, 9-bit-input table
    -- see the module docstring for why 9 input bits are needed for an
    "8-bit" S-box). Uses several block/key sizes and plaintext/key pairs beyond
    the hardcoded official test vectors above, so any future edit to either
    implementation that breaks their equivalence is caught immediately.
    """
    configs_and_inputs = [
        (32, 64, 32, (0x00000000, 0x0000000000000000)),
        (32, 64, 32, (0xffffffff, 0xffffffffffffffff)),
        (32, 64, 32, (0x9e3a05c1, 0x1122334455667788)),
        (48, 96, 36, (0x0badc0de1337, 0xdeadbeefcafebabe01234567)),
        (64, 128, 44, (0x0123456789abcdef, 0xfedcba9876543210aaaaaaaaaaaaaaaa)),
        (128, 256, 72, (0x0011223344556677889900aabbccddee,
                        0x102030405060708090a0b0c0d0e0f0010203040506070809000a0b0c0d0e0f0)),
    ]
    for block_bit_size, key_bit_size, number_of_rounds, (plaintext, key) in configs_and_inputs:
        bitwise = SimonBlockCipher(
            block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=number_of_rounds
        )
        sbox = SimonSboxBlockCipher(
            block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=number_of_rounds
        )
        assert bitwise.evaluate([plaintext, key]) == sbox.evaluate([plaintext, key])
