from claasp.ciphers.block_ciphers.prince_v2_block_cipher import PrinceV2BlockCipher

"""
The technical specifications along with the test vectors can be found here: https://eprint.iacr.org/2020/1269.pdf
"""

def test_princeV2_block_cipher():
    prince_v2 = PrinceV2BlockCipher()
    plaintext = 0x0000000000000000
    key = 0x00000000000000000000000000000000
    ciphertext = 0x0125fc7359441690
    assert prince_v2.evaluate([plaintext, key]) == ciphertext

    prince_v2 = PrinceV2BlockCipher()
    plaintext = 0xffffffffffffffff
    key = 0x00000000000000000000000000000000
    ciphertext = 0x832bd46f108e7857
    assert prince_v2.evaluate([plaintext, key]) == ciphertext

    prince_v2 = PrinceV2BlockCipher()
    plaintext = 0x0000000000000000
    key = 0xffffffffffffffff0000000000000000
    ciphertext = 0xee873b2ec447944d
    assert prince_v2.evaluate([plaintext, key]) == ciphertext

    prince_v2 = PrinceV2BlockCipher()
    plaintext = 0x0000000000000000
    key =  0x0000000000000000ffffffffffffffff
    ciphertext = 0x0ac6f9cd6e6f275d
    assert prince_v2.evaluate([plaintext, key]) == ciphertext

    prince_v2 = PrinceV2BlockCipher()
    plaintext = 0x0123456789abcdef
    key = 0x0123456789abcdeffedcba9876543210
    ciphertext = 0x603cd95fa72a8704
    assert prince_v2.evaluate([plaintext, key]) == ciphertext
