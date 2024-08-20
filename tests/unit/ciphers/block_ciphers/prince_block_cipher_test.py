from claasp.ciphers.block_ciphers.prince_block_cipher import PrinceBlockCipher


def test_prince_block_cipher():
    prince = PrinceBlockCipher()
    plaintext = 0x0
    key = 0x0
    ciphertext = 0x818665aa0d02dfda
    assert prince.evaluate([plaintext, key]) == ciphertext
    assert prince.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    present = PrinceBlockCipher()
    plaintext = 0xffffffffffffffff
    key = 0x00000000000000000000000000000000
    ciphertext = 0x604ae6ca03c20ada
    assert present.evaluate([plaintext, key]) == ciphertext
    assert present.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext