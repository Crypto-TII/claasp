import pytest

from claasp.cipher_modules.component_analysis_tests import CipherComponentsAnalysis, branch_number
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.name_mappings import MIX_COLUMN


def test_aes_block_cipher():
    aes = ToyAESBlockCipher()
    assert aes.type == 'block_cipher'
    assert aes.family_name == 'aes_block_cipher'
    assert aes.number_of_rounds == 10
    assert aes.id == 'aes_block_cipher_k128_p128_o128_r10'
    assert aes.component_from(0, 0).id == 'xor_0_0'
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes128_block_cipher():
    aes = ToyAESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_8_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=8, state_size=3)
    key = 0x2b7e151628aed2a6ab
    plaintext = 0x6bc1bee22e409f96e9
    ciphertext = 0xf8666f8d0ba0dcfced
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_8_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=8, state_size=2)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0xdbbdd038
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_4_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=4)
    key = 0x2b7e151628aed2a6
    plaintext = 0x6bc1bee22e409f96
    ciphertext = 0x0e51ff61dac37a78
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_4_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=3)
    key = 0b100111100101111110011110010111110000
    plaintext = 0b100111100101111110011110010111110000
    ciphertext = 0x3a54a9d02
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext


def test_aes_4_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=2)
    key = 0x2b7e
    plaintext = 0x6bc1
    ciphertext = 0xa1fe
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=4)
    key = 0x2b7e151628ae
    plaintext = 0x6bc1bee22e40
    ciphertext = 0x33d9c96fe11c
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=3)
    key = 0b101101101101101101100011011
    plaintext = 0b100001111011110101101100010
    ciphertext = 0x0595c25b
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=2)
    key = 0x2b7
    plaintext = 0x6bc
    ciphertext = 0x2c8
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=4)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0x41bed50e
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=3)
    key = 0b101101101100011011
    plaintext = 0b011110101101100010
    ciphertext = 0x00de3c
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=2)
    key = 0x2b
    plaintext = 0x6b
    ciphertext = 0x1f
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext


# Computationally pinned MDS / word-wise differential branch number of every MixColumn matrix
# used by ToyAESBlockCipher, keyed by (word_size, state_size). These values were verified with
# Sage (GF(2^word_size), modulus taken from ToyAESBlockCipher.irreducible_polynomial) and are not
# assumed: every square submatrix (all minors) of each matrix was checked for singularity, and the
# branch number was computed by brute force over all nonzero word-wise input differences.
#
# (word_size=2, state_size=4) is the sole non-MDS entry. This is not a bug to "fix" by picking
# different matrix constants: GF(2^2) = GF(4) is provably too small to admit ANY 4x4 MDS matrix
# (see the ToyAESBlockCipher class docstring for the underlying coding-theory argument and the
# exhaustive/random search that corroborates it), so branch number 3 (instead of the optimal 5)
# is an inherent limitation of this toy parametrization.
AES_MATRIX_MDS_STATUS = {
    (2, 2): (True, 3),
    (3, 2): (True, 3),
    (4, 2): (True, 3),
    (8, 2): (True, 3),
    (2, 3): (True, 4),
    (3, 3): (True, 4),
    (4, 3): (True, 4),
    (8, 3): (True, 4),
    (2, 4): (False, 3),
    (3, 4): (True, 5),
    (4, 4): (True, 5),
    (8, 4): (True, 5),
}


@pytest.mark.parametrize("word_size, state_size", list(AES_MATRIX_MDS_STATUS.keys()))
def test_aes_matrix_mds_status(word_size, state_size):
    expected_is_mds, expected_branch_number = AES_MATRIX_MDS_STATUS[(word_size, state_size)]

    aes = ToyAESBlockCipher(number_of_rounds=3, word_size=word_size, state_size=state_size)
    mix_column_component = next(c for c in aes.get_all_components() if c.type == MIX_COLUMN)

    assert CipherComponentsAnalysis(aes)._is_mds(mix_column_component) == expected_is_mds
    assert branch_number(mix_column_component, "differential", "word") == expected_branch_number
    # Branch number can never exceed the theoretical optimum n+1 for an n x n diffusion matrix,
    # and MDS is exactly equivalent to achieving that optimum.
    assert expected_branch_number <= state_size + 1
    assert expected_is_mds == (expected_branch_number == state_size + 1)
