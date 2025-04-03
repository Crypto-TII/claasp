import pytest

from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_skinny_block_cipher():
    skinny = SkinnyBlockCipher()
    assert skinny.type == "block_cipher"
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

    # Skinny-128-128
    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=40)
    plaintext = 0xF20ADB0EB08B648A3B2EEED1F0ADDA14
    key = 0x4F55CFB0520CAC52FD92C15F37073E93
    ciphertext = 0x22FF30D498EA62D7E45B476E33675B74
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext
