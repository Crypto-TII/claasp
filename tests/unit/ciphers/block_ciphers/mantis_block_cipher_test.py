from claasp.ciphers.block_ciphers.mantis_block_cipher import MantisBlockCipher

"""
MANTIS block cipher validation
Test vectors reproduced from Beierle et al., "The SKINNY Family of Block Ciphers and its Low-Latency Variant MANTIS"
(IACR ePrint 2016/660): https://eprint.iacr.org/2016/660.pdf
"""

def test_mantis_block_cipher():
    mantis5 = MantisBlockCipher(number_of_rounds=5)
    plaintext = 0x3b5c77a4921f9718
    key = 0x92f09952c625e3e9d7a060f714c0292b
    tweak = 0xba912e6f1055fed2
    ciphertext = 0xd6522035c1c0c6c1
    assert mantis5.evaluate([plaintext, key, tweak]) == ciphertext

    mantis6 = MantisBlockCipher(number_of_rounds=6)
    plaintext = 0xd6522035c1c0c6c1
    key = 0x92f09952c625e3e9d7a060f714c0292b
    tweak = 0xba912e6f1055fed2
    ciphertext = 0x60e43457311936fd
    assert mantis6.evaluate([plaintext, key, tweak]) == ciphertext

    mantis7 = MantisBlockCipher(number_of_rounds=7)
    plaintext = 0x60e43457311936fd
    key = 0x92f09952c625e3e9d7a060f714c0292b
    tweak = 0xba912e6f1055fed2
    ciphertext = 0x308e8a07f168f517
    assert mantis7.evaluate([plaintext, key, tweak]) == ciphertext

    mantis8 = MantisBlockCipher(number_of_rounds=8)
    plaintext = 0x308e8a07f168f517
    key = 0x92f09952c625e3e9d7a060f714c0292b
    tweak = 0xba912e6f1055fed2
    ciphertext = 0x971ea01a86b410bb
    assert mantis8.evaluate([plaintext, key, tweak]) == ciphertext
