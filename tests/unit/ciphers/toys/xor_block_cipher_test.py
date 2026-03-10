from claasp.ciphers.toys.xor_block_cipher import XorBlockCipher


def test_xor_block_cipher_evaluate_all_ones():
    cipher = XorBlockCipher(block_bit_size=8)

    assert cipher.evaluate([0xFF, 0xFF]) == 0
