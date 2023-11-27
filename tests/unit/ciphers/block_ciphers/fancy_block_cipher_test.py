from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher


def test_fancy_block_cipher():
    fancy = FancyBlockCipher()
    assert fancy.type == 'block_cipher'
    assert fancy.family_name == 'fancy_block_cipher'
    assert fancy.number_of_rounds == 20
    assert fancy.id == 'fancy_block_cipher_p24_k24_o24_r20'
    assert fancy.component_from(0, 0).id == 'sbox_0_0'

    fancy = FancyBlockCipher(number_of_rounds=4)
    assert fancy.number_of_rounds == 4
    assert fancy.id == 'fancy_block_cipher_p24_k24_o24_r4'
    assert fancy.component_from(3, 0).id == 'sbox_3_0'

    fancy = FancyBlockCipher()
    key = 0xFFFFFF
    plaintext = 0x000000
    ciphertext = 0xca3417
    assert fancy.evaluate([plaintext, key]) == ciphertext

    fancy = FancyBlockCipher(number_of_rounds=1)
    ciphertext = 0xfedcba
    assert fancy.evaluate([plaintext, key]) == ciphertext
