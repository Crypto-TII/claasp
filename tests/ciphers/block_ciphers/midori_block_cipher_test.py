import pytest

from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_midori_block_cipher():
    midori = MidoriBlockCipher()
    assert midori.type == 'block_cipher'
    assert midori.family_name == 'midori'
    assert midori.number_of_rounds == 16
    assert midori.id == 'midori_p64_k128_o64_r16'
    assert midori.component_from(0, 0).id == 'xor_0_0'

    midori = MidoriBlockCipher(number_of_rounds=4)
    assert midori.number_of_rounds == 4
    assert midori.id == 'midori_p64_k128_o64_r4'
    assert midori.component_from(3, 0).id == 'sbox_3_0'

    midori = MidoriBlockCipher()
    plaintext = 0x42c20fd3b586879e
    key = 0x687ded3b3c85b3f35b1009863e2a8cbf
    ciphertext = 0x66bcdc6270d901cd
    assert midori.evaluate([plaintext, key]) == ciphertext
    assert midori.test_against_reference_code(2) is True

    midori = MidoriBlockCipher(block_bit_size=128)
    plaintext = 0x51084ce6e73a5ca2ec87d7babc297543
    key = 0x687ded3b3c85b3f35b1009863e2a8cbf
    ciphertext = 0x1e0ac4fddff71b4c1801b73ee4afc83d
    assert midori.evaluate([plaintext, key]) == ciphertext
    assert midori.test_against_reference_code(2) is True
