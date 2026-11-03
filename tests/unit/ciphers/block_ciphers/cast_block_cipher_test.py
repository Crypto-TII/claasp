from claasp.ciphers.block_ciphers.cast_block_cipher import CastBlockCipher

def test_basic_cast_block_cipher():
    """ Init test"""
    cast = CastBlockCipher()
    assert cast.key_bit_size == 128
    assert cast.nrounds == 16
    assert cast.family_name == 'cast_block_cipher'
    assert cast.type == 'block_cipher'

def test_custom_key_nrounds():
    """ Custom n_rounds and key_bit_size"""
    cast = CastBlockCipher(key_bit_size = 56, number_of_rounds = 10)
    assert cast.key_bit_size == 56
    assert cast.nrounds == 10

def test_vector_128_bit():
    """ Test Vector 128 bit, same to doctest, from [A1997]_."""
    cast = CastBlockCipher(key_bit_size = 128)
    assert cast.nrounds == 16
    key = 0x0123456712345678234567893456789A
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0x238B4FE5847E44B2
    assert cast.evaluate([key, plaintext]) == ciphertext

def test_vector_80_bit():
    """ Test Vector 80 bit, 12 rounds, from [A1997]_."""
    cast = CastBlockCipher(key_bit_size = 80)
    assert cast.nrounds == 12
    key = 0x01234567123456782345
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0xEB6A711A2C02271B
    assert cast.evaluate([key, plaintext]) == ciphertext

def test_vector_40_bit():
    """ Test Vector 40 bit, 12 rounds, from [A1997]_."""
    cast = CastBlockCipher(key_bit_size=40)
    assert cast.nrounds == 12
    key = 0x0123456712
    plaintext = 0x0123456789ABCDEF
    ciphertext = 0x7AC816D16E9B302E
    assert cast.evaluate([key, plaintext]) == ciphertext
