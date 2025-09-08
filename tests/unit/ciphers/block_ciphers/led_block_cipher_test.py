"""LED tests

Test vectors from https://eprint.iacr.org/2012/600.pdf
"""

import pytest

from claasp.ciphers.block_ciphers.led_block_cipher import LedBlockCipher
from claasp.name_mappings import BLOCK_CIPHER

@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_led_block_cipher():
    led = LedBlockCipher()
    assert led.cipher_type == BLOCK_CIPHER
    assert led.family_name == "led"
    assert led.number_of_rounds == 8
    assert led.id == "led_p64_k64_o64_r8"
    assert led.component_from(0, 0).id == "xor_0_0"

    plaintext = 0x0000000000000000
    key = 0x0000000000000000
    ciphertext = 0x39C2401003A0C798
    assert led.evaluate([plaintext, key]) == ciphertext
    assert led.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    led = LedBlockCipher()
    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF
    ciphertext = 0xA003551E3893FC58
    assert led.evaluate([plaintext, key]) == ciphertext
    assert led.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext