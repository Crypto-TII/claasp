from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher

def test_twine_block_cipher():
    twine = TwineBlockCipher()
    assert twine.type == 'block_cipher'
    assert twine.family_name == 'twine'
    assert twine.number_of_rounds == 36
    assert twine.id == 'twine_p64_k80_o64_r32'
    plaintext = 0
    key = 0
    ciphertext = 0x7393C133CDE3F8DB
    assert twine.evaluate([plaintext, key]) == ciphertext
    assert twine.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    plaintext = 0x123456789ABCDEF
    key = 0x00112233445566778899
    ciphertext = 0x7C1F0F80B1DF9C28
    assert twine.evaluate([plaintext, key]) == ciphertext
    assert twine.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    twine = TwineBlockCipher(key_bit_size=80, number_of_rounds=36)
    key = 0x00112233445566778899AABBCCDDEEFF
    ciphertext = 0x979FF9B379B5A9B8
    assert twine.evaluate([plaintext, key]) == ciphertext
    assert twine.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
