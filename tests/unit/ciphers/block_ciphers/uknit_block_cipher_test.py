from claasp.ciphers.block_ciphers.uknit_block_cipher import UKNITBlockCipher

"""
Reference for test vectors: [HKPT2026]_.
"""

def test_structure():
    """Init test"""
    uknit = UKNITBlockCipher()
    assert uknit.key_bit_size == 128
    assert uknit.block_bit_size == 64
    assert uknit.nrounds == 12
    assert uknit.family_name == 'uknit_block_cipher'
    assert uknit.type == 'block_cipher'

def test_vector_1():
    """Test Vector 1, from uKNIT test vectors"""
    uknit = UKNITBlockCipher()
    key = 0x00000000000000000000000000000000
    plaintext = 0x0000000000000000
    ciphertext = 0x034af0b3c687e424
    assert uknit.evaluate([plaintext, key]) == ciphertext
    assert uknit.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

def test_vector_2():
    """Test Vector 2, from uKNIT test vectors, same as doctest"""
    uknit = UKNITBlockCipher()
    key = 0x0123456789abcdef0123456789abcdef
    plaintext = 0x0123456789abcdef
    ciphertext = 0x7d4ef882c1f42dba
    assert uknit.evaluate([plaintext, key]) == ciphertext
    assert uknit.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

def test_vector_3():
    """Test Vector 3, from uKNIT test vectors"""
    uknit = UKNITBlockCipher()
    key = 0xffffffffffffffffffffffffffffffff
    plaintext = 0xffffffffffffffff
    ciphertext = 0xdb058583df8f186f
    assert uknit.evaluate([plaintext, key]) == ciphertext
    assert uknit.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

def test_vector_4():
    """Test Vector 4, from uKNIT test vectors"""
    uknit = UKNITBlockCipher()
    key = 0xfedcba98765432100123456789abcdef
    plaintext = 0x1111111111111111
    ciphertext = 0x7c8ddaf0fead3409
    assert uknit.evaluate([plaintext, key]) == ciphertext
    assert uknit.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext