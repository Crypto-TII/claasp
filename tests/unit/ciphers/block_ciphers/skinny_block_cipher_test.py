"""SKINNY tests

Test vectors from https://eprint.iacr.org/2016/660.pdf
"""
import pytest

from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
from claasp.name_mappings import BLOCK_CIPHER


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_skinny_block_cipher():
    skinny = SkinnyBlockCipher()
    assert skinny.type == BLOCK_CIPHER
    assert skinny.family_name == "skinny"
    assert skinny.number_of_rounds == 32
    assert skinny.id == "skinny_p64_k64_o64_r32"
    assert skinny.component_from(0, 0).id == "constant_0_0"

    # Skinny-64-64
    plaintext = 0x06034F957724D19D
    key = 0xF5269826FC681238
    ciphertext = 0xBB39DFB2429B8AC7
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext

    # Skinny-64-128
    skinny = SkinnyBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=36)
    plaintext = 0xCF16CFE8FD0F98AA
    key = 0x9EB93640D088DA6376A39D1C8BEA71E1
    ciphertext = 0x6CEDA1F43DE92B9E
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext

    # Skinny-64-192
    skinny = SkinnyBlockCipher(block_bit_size=64, key_bit_size=192, number_of_rounds=40)
    plaintext = 0x530C61D35E8663C3
    key = 0xED00C85B120D68618753E24BFD908F60B2DBB41B422DFCD0
    ciphertext = 0xDD2CF1A8F330303C
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext

    # Skinny-128-128
    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=40)
    plaintext = 0xF20ADB0EB08B648A3B2EEED1F0ADDA14
    key = 0x4F55CFB0520CAC52FD92C15F37073E93
    ciphertext = 0x22FF30D498EA62D7E45B476E33675B74
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext

    # Skinny-128-256
    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=256, number_of_rounds=48)
    plaintext = 0x3A0C47767A26A68DD382A695E7022E25
    key = 0x009CEC81605D4AC1D2AE9E3085D7A1F31AC123EBFC00FDDCF01046CEEDDFCAB3
    ciphertext = 0xB731D98A4BDE147A7ED4A6F16B9B587F
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext

    # Skinny-128-384
    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=56)
    plaintext = 0xA3994B66AD85A3459F44E92B08F550CB
    key = 0xDF889548CFC7EA52D296339301797449AB588A34A47F1AB2DFE9C8293FBEA9A5AB1AFAC2611012CD8CEF952618C3EBE8
    ciphertext = 0x94ECF589E2017C601B38C6346A10DCFA
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext
