"""BAKSHEESH tests

Test vectors from https://eprint.iacr.org/2023/750.pdf
"""

import pytest

from claasp.ciphers.block_ciphers.baksheesh_block_cipher import BaksheeshBlockCipher
from claasp.name_mappings import BLOCK_CIPHER


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_baksheesh_block_cipher():
    baksheesh = BaksheeshBlockCipher()
    assert baksheesh.type == BLOCK_CIPHER
    assert baksheesh.family_name == "baksheesh"
    assert baksheesh.number_of_rounds == 35
    assert baksheesh.id == "baksheesh_p128_k128_o128_r35"
    assert baksheesh.component_from(0, 0).id == "xor_0_0"

    # Test 5
    plaintext = 0x11111111111111111111111111111111
    key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ciphertext = 0x806F0CF45B94F0370206975FE78AC10F
    assert baksheesh.evaluate([plaintext, key]) == ciphertext
    assert baksheesh.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    # Test 6
    baksheesh = BaksheeshBlockCipher()
    plaintext = 0x789A789A789A789A789A789A789A789A
    key = 0x76543210032032032032032032032032
    ciphertext = 0xAE654B5333B876584F8E8DD54F4E490A
    assert baksheesh.evaluate([plaintext, key]) == ciphertext
    assert baksheesh.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    # Test 7
    baksheesh = BaksheeshBlockCipher()
    plaintext = 0xB6E4789AB6E4789AB6E4789AB6E4789A
    key = 0x23023023023023023023023001234567
    ciphertext = 0x3DBBDF7FE254CC0BE396A753442DCCAD
    assert baksheesh.evaluate([plaintext, key]) == ciphertext
    assert baksheesh.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    # Test 8
    baksheesh = BaksheeshBlockCipher()
    plaintext = 0xE6517531ABF63F3D7805E126943A081C
    key = 0x5920EFFB52BC61E33A98425321E76915
    ciphertext = 0xFC7E61FEE3D587308CA7BC594EBF3244
    assert baksheesh.evaluate([plaintext, key]) == ciphertext
    assert baksheesh.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
