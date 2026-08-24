"""Test vectors from Table 10 of https://eprint.iacr.org/2014/084.pdf"""

from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher


def test_rectangle_block_cipher():
    rectangle = RectangleBlockCipher(number_of_rounds=4)
    assert rectangle.number_of_rounds == 4
    assert rectangle.id == 'rectangle_p64_k80_o64_r4'
    assert rectangle.component_from(3, 0).id == 'xor_3_0'

    rectangle = RectangleBlockCipher()
    plaintext = 0x0000000000000000
    key = 0x00000000000000000000
    ciphertext = 0x0874e8b1e3542d96
    assert rectangle.evaluate([plaintext, key]) == ciphertext
    assert rectangle.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    plaintext = 0xffffffffffffffff
    key = 0xffffffffffffffffffff
    ciphertext = 0x0112ae3daa349945
    assert rectangle.evaluate([plaintext, key]) == ciphertext
    assert rectangle.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    rectangle = RectangleBlockCipher(key_bit_size=128)
    assert rectangle.id == 'rectangle_p64_k128_o64_r25'
    plaintext = 0x0000000000000000
    key = 0x00000000000000000000000000000000
    ciphertext = 0x99ee44a43613aee6
    assert rectangle.evaluate([plaintext, key]) == ciphertext
    assert rectangle.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    plaintext = 0xffffffffffffffff
    key = 0xffffffffffffffffffffffffffffffff
    ciphertext = 0x7a464a15efeee83e
    assert rectangle.evaluate([plaintext, key]) == ciphertext
    assert rectangle.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
