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
    plaintext = 0x06034f957724d19d
    key = 0xf5269826fc681238
    ciphertext = 0xbb39dfb2429b8ac7
    assert skinny.evaluate([plaintext, key]) == ciphertext
    assert skinny.evaluate_vectorized([plaintext, key], evaluate_api = True) == ciphertext
