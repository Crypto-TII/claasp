from claasp.ciphers.block_ciphers.bea1_block_cipher import BEA1BlockCipher


def test_bea1_block_cipher():
    bea = BEA1BlockCipher()
    assert bea.type == 'block_cipher'
    assert bea.family_name == 'bea1_block_cipher'
    assert bea.number_of_rounds == 11

    bea = BEA1BlockCipher()
    key = 0x8cdd0f3459fb721e798655298d5c1
    pt = 0x47a57eff5d6475a68916
    ciphertext = 0x439d5298656eccc67dee
    assert bea.evaluate([key,pt]) == ciphertext

    bea = BEA1BlockCipher()
    key = 0xe2f458684631d4b069dd178cf7ace9
    pt = 0x4e7a51e6d08c7a3515f0
    ciphertext = 0xa36097ea1bdcddf8b06d
    assert bea.evaluate([key,pt]) == ciphertext
