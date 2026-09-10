from claasp.ciphers.block_ciphers.bipbip_block_cipher import BipBipBlockCipher

"""
Implementation of BipBip is based on [BDDGR23]_. 
No official test vectors could be found, so the test vectors has been generated independently.
"""

def test_structure():
    bipbip = BipBipBlockCipher()
    assert bipbip.nrounds == 11
    assert bipbip.sh1 == 3
    assert bipbip.cr == 5
    assert bipbip.sh2 == 3

def test_0():
    bipbip = BipBipBlockCipher()
    plaintext = 0x000000
    key = 0x0000000000000000000000000000000000000000000000000000000000000000
    tweak = 0x0000000000
    ciphertext = 0x7eab9b
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_1():
    bipbip = BipBipBlockCipher()
    plaintext = 0xffffff
    key = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    tweak = 0xffffffffff
    ciphertext = 0x7f15bc
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_single_1():
    bipbip = BipBipBlockCipher()
    plaintext = 0x000001
    key = 0x0000000000000000000000000000000000000000000000000000000000000000
    tweak = 0x0000000000
    ciphertext = 0xb9ede5
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_mixed_values():
    bipbip = BipBipBlockCipher()
    plaintext = 0x5a5a5a
    key = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    tweak = 0x8899aabbcc
    ciphertext = 0x98f794
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_0_custom_rounds():
    bipbip = BipBipBlockCipher(number_of_shell_rounds_1=1, number_of_core_rounds=2, number_of_shell_rounds_2=1)
    plaintext = 0x000000
    key = 0x0000000000000000000000000000000000000000000000000000000000000000
    tweak = 0x0000000000
    ciphertext = 0xf88711
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_1_custom_rounds():
    bipbip = BipBipBlockCipher(number_of_shell_rounds_1=1, number_of_core_rounds=2, number_of_shell_rounds_2=1)
    plaintext = 0xffffff
    key = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    tweak = 0xffffffffff
    ciphertext = 0x12f519
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_single_1_custom_rounds():
    bipbip = BipBipBlockCipher(number_of_shell_rounds_1=1, number_of_core_rounds=2, number_of_shell_rounds_2=1)
    plaintext = 0x000001
    key = 0x0000000000000000000000000000000000000000000000000000000000000000
    tweak = 0x0000000000
    ciphertext = 0x4e21f8
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext


def test_mixed_value_custom_rounds():
    bipbip = BipBipBlockCipher(number_of_shell_rounds_1=1, number_of_core_rounds=2, number_of_shell_rounds_2=1)
    plaintext = 0x5a5a5a
    key = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    tweak = 0x8899aabbcc
    ciphertext = 0x13e29f
    assert bipbip.evaluate([plaintext, key, tweak]) == ciphertext
    assert bipbip.evaluate_vectorized([plaintext, key, tweak], evaluate_api=True) == ciphertext