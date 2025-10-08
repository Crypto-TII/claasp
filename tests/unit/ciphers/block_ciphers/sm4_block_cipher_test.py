from claasp.ciphers.block_ciphers.sm4_block_cipher import SM4

"""
The technical specifications along with the test vectors can be found here: http://www.gmbz.org.cn/upload/2025-01-23/1737625646289030731.pdf
and https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10.
"""


def test_sm4_block_cipher():
    sm4 = SM4()
    key = 0x0123456789ABCDEFFEDCBA9876543210
    plaintext = 0x0123456789ABCDEFFEDCBA9876543210
    ciphertext = 0x681EDF34D206965E86B3E94F536E4246
    assert sm4.evaluate([key, plaintext]) == ciphertext
    assert sm4.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext


def test_sm4_block_cipher():
    sm4 = SM4()
    key = 0xFEDCBA98765432100123456789ABCDEF
    plaintext = 0x000102030405060708090A0B0C0D0E0F
    ciphertext = 0xF766678F13F01ADEAC1B3EA955ADB594
    assert sm4.evaluate([key, plaintext]) == ciphertext
    assert sm4.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
