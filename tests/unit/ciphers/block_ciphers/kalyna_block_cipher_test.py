"""Kalyna tests

Reference: https://eprint.iacr.org/2015/650.pdf
"""

from claasp.ciphers.block_ciphers.kalyna_block_cipher import KalynaBlockCipher


def test_kalyna_block_cipher():
    kalyna = KalynaBlockCipher()
    key = 0x0F0E0D0C0B0A09080706050403020100
    plaintext = 0x1F1E1D1C1B1A19181716151413121110
    ciphertext = 0x06ADD2B439EAC9E120AC9B777D1CBF81
    assert kalyna.evaluate([key, plaintext]) == ciphertext
    assert kalyna.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
