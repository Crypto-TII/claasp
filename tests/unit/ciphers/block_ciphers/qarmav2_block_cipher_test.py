import pytest

from claasp.ciphers.block_ciphers.qarmav2_block_cipher import QARMAv2BlockCipher


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_qarmav2_block_cipher():
    qarmav2 = QARMAv2BlockCipher(number_of_rounds = 4)
    assert qarmav2.type == 'block_cipher'
    assert qarmav2.family_name == 'qarmav2_block_cipher'
    assert qarmav2.number_of_rounds == 9
    assert qarmav2.id == 'qarmav2_block_cipher_k128_p64_i128_o64_r9'
    assert qarmav2.component_from(0, 0).id == 'constant_0_0'

    qarmav2 = QARMAv2BlockCipher(number_of_rounds = 4)
    key = 0x0123456789abcdeffedcba9876543210
    plaintext = 0x0000000000000000
    tweak = 0x7e5c3a18f6d4b2901eb852fc9630da74
    ciphertext = 0x2cc660354929f2ca
    assert qarmav2.evaluate([key, plaintext, tweak]) == ciphertext

    qarmav2 = QARMAv2BlockCipher(number_of_rounds = 9)
    key = 0x0123456789abcdeffedcba9876543210
    plaintext = 0x0000000000000000
    tweak = 0x7e5c3a18f6d4b2901eb852fc9630da74
    ciphertext = 0xd459510ab82c66fc
    assert qarmav2.evaluate([key, plaintext, tweak]) == ciphertext

    #qarmav2 = QARMAv2BlockCipher(number_of_layers = 2, number_of_rounds = 9, key_bit_size = 256, tweak_bit_size = 256)
    #key = 0x00102030405060708090a0b0c0d0e0f00f0e0d0c0b0a09080706050403020100
    #plaintext = 0x00000000000000000000000000000000
    #tweak = 0x7e5c3a18f6d4b290e5c3a18f6d4b29071eb852fc630da741b852fc960da741eb
    #ciphertext = 0x361262e2ecf88f03f4ea898d6a4f412f
    #assert qarmav2.evaluate([key, plaintext, tweak]) == ciphertext
