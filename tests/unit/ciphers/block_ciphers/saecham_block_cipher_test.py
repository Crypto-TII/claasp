"""
Tests for SaechamBlockCipher.

The paper test vector (key, plaintext → ciphertext) is taken from

.. [DampersSAECHAM2025] Dampers, A. et al. (2025). SAECHAM: A Lightweight
   Block Cipher based on CHAM. Preprint / implementation repository:
   https://github.com/dampers/SAECHAM-implementations

The additional test vectors (all-zero and all-one inputs) were generated with
the reference Python implementation in playground/claasp/cham/reference.py
and cross-checked against the MSP430 assembly reference implementation from
the same repository.
"""

from claasp.ciphers.block_ciphers.saecham_block_cipher import SaechamBlockCipher


def test_saecham_block_cipher_structure():
    saecham = SaechamBlockCipher()
    assert saecham.type == 'block_cipher'
    assert saecham.family_name == 'saecham_block_cipher'
    assert saecham.number_of_rounds == 88
    assert saecham.id == 'saecham_block_cipher_k128_p64_o64_r88'
    # Round 0 first component: ROL(k[0], 1) from the key schedule
    assert saecham.component_from(0, 0).id == 'rot_0_0'

    reduced = SaechamBlockCipher(number_of_rounds=4)
    assert reduced.number_of_rounds == 4
    assert reduced.id == 'saecham_block_cipher_k128_p64_o64_r4'
    assert reduced.component_from(3, 0).id == 'rot_3_0'


def test_saecham_paper_vector():
    """Test vector from [DampersSAECHAM2025]_."""
    saecham = SaechamBlockCipher()
    key = 0x010003020504070609080b0a0d0c0f0e
    pt  = 0x1100332255447766
    assert saecham.evaluate([key, pt]) == 0xfe475393e6ba01f1
    assert saecham.evaluate_vectorized([key, pt], evaluate_api=True) == 0xfe475393e6ba01f1


def test_saecham_generated_vectors():
    """Additional vectors generated from the reference implementation."""
    saecham = SaechamBlockCipher()

    # All-zero plaintext and key
    assert saecham.evaluate([0, 0]) == 0x86e8c489f5905be9

    # All-one plaintext and key (64-bit pt, 128-bit key)
    key_ones = (1 << 128) - 1
    pt_ones  = (1 << 64)  - 1
    assert saecham.evaluate([key_ones, pt_ones]) == 0x8558aebef40b15fa
