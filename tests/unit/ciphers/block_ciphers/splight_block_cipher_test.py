import pytest

from claasp.ciphers.block_ciphers.splight_block_cipher import SplightBlockCipher
from claasp.name_mappings import BLOCK_CIPHER


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_splight_block_cipher():
    splight = SplightBlockCipher()
    assert splight.type == BLOCK_CIPHER
    assert splight.family_name == "splight"
    assert splight.number_of_rounds == 32
    assert splight.id == "splight_p64_k128_o64_r32"
    assert splight.component_from(0, 0).id == "sbox_0_0"

    # Test vectors from https://ieeexplore.ieee.org/abstract/document/11501825
    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF0123456789ABCDEF
    ciphertext = 0x1A6CC67730856F30
    assert splight.evaluate([plaintext, key]) == ciphertext
    assert splight.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
