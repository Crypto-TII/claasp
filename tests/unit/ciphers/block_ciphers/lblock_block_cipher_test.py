from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher


def test_lblock_block_cipher():
    lblock = LBlockBlockCipher()
    assert lblock.type == 'block_cipher'
    assert lblock.family_name == 'lblock'
    assert lblock.number_of_rounds == 32
    assert lblock.id == 'lblock_p64_k80_o64_r32'
    plaintext = 0
    key = 0
    ciphertext = 0xC218185308E75BCD
    assert lblock.evaluate([plaintext, key]) == ciphertext

    plaintext = 0x0123456789abcdef
    key = 0x0123456789abcdeffedc
    ciphertext = 0x4B7179D8EBEE0C26
    assert lblock.evaluate([plaintext, key]) == ciphertext
