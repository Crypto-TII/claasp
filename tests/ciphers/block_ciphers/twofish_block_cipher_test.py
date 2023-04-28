import pytest

from claasp.ciphers.block_ciphers.twofish_block_cipher import TwofishBlockCipher


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_twofish_block_cipher():
    twofish = TwofishBlockCipher()
    assert twofish.type == 'block_cipher'
    assert twofish.family_name == 'twofish_block_cipher'
    assert twofish.number_of_rounds == 16
    assert twofish.id == 'twofish_block_cipher_k128_p128_o128_r16'
    assert twofish.component_from(0, 0).id == 'linear_layer_0_0'

    twofish = TwofishBlockCipher(number_of_rounds=4)
    assert twofish.number_of_rounds == 4
    assert twofish.id == 'twofish_block_cipher_k128_p128_o128_r4'
    assert twofish.component_from(3, 0).id == 'constant_3_0'

    cipher = TwofishBlockCipher(key_length=256, number_of_rounds=16)
    key = 0xD43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F
    plaintext = 0x90AFE91BB288544F2C32DC239B2635E6
    ciphertext = 0x6CB4561C40BF0A9705931CB6D408E7FA
    assert cipher.evaluate([key, plaintext]) == ciphertext

    two_fish = TwofishBlockCipher(key_length=128, number_of_rounds=16)
    key = 0x9F589F5CF6122C32B6BFEC2F2AE8C35A
    plaintext = 0xD491DB16E7B1C39E86CB086B789F5419
    ciphertext = 0x019F9809DE1711858FAAC3A3BA20FBC3
    assert two_fish.evaluate([key, plaintext]) == ciphertext

    two_fish = TwofishBlockCipher(key_length=192, number_of_rounds=16)
    key = 0x88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44
    plaintext = 0x39DA69D6BA4997D585B6DC073CA341B2
    ciphertext = 0x182B02D81497EA45F9DAACDC29193A65
    assert two_fish.evaluate([key, plaintext]) == ciphertext
