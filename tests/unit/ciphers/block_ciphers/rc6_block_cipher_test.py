"""Test vectors from the Appendix of The RC6 Block Cipher, v1.1 (Rivest, Robshaw, Sidney, Yin, 1998)"""

from claasp.ciphers.block_ciphers.rc6_block_cipher import RC6BlockCipher


def test_rc6_block_cipher():
    rc6 = RC6BlockCipher(number_of_rounds=4)
    assert rc6.id == 'rc6_p128_k128_o128_r4'
    assert rc6.component_from(3, 3).id == 'modmul_3_3'

    rc6 = RC6BlockCipher()
    plaintext = 0x02132435465768798a9bacbdcedfe0f1
    key = 0x0123456789abcdef0112233445566778
    ciphertext = 0x524e192f4715c6231f51f6367ea43f18
    assert rc6.evaluate([plaintext, key]) == ciphertext

    rc6 = RC6BlockCipher(key_bit_size=256)
    key = 0x0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe
    ciphertext = 0xc8241816f0d7e48920ad16a1674e5d48
    assert rc6.evaluate([plaintext, key]) == ciphertext

    # The following test vector has been obtained from
    # https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-3

    rc6 = RC6BlockCipher(word_size=8, key_bit_size=32, number_of_rounds=12)
    key = 0x00010203
    plaintext = 0x00010203
    ciphertext = 0xAEFC4612
    assert rc6.evaluate([plaintext, key]) == ciphertext
