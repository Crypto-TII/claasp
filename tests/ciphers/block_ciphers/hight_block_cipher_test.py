from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher


def test_hight_block_cipher():
    hight = HightBlockCipher()
    assert hight.type == 'block_cipher'
    assert hight.family_name == 'hight'
    assert hight.number_of_rounds == 32
    assert hight.id == 'hight_p64_k128_o64_r32'
    assert hight.component_from(0, 0).id == 'modadd_0_0'

    hight = HightBlockCipher(number_of_rounds=3)
    assert hight.number_of_rounds == 3
    assert hight.id == 'hight_p64_k128_o64_r3'
    assert hight.component_from(2, 0).id == 'constant_2_0'

    hight = HightBlockCipher(block_bit_size=64,
                             key_bit_size=128,
                             number_of_rounds=3,
                             sub_keys_zero=True,
                             transformations_flag=False)
    plaintext = 0x0011223344556677
    key = 0x0
    assert hight.evaluate([plaintext, key], verbosity=False) == 0x1055ddee99ba66e0

    hight = HightBlockCipher(block_bit_size=64,
                             key_bit_size=128,
                             number_of_rounds=10,
                             transformations_flag=False)
    key = 0x000000066770000000a0000000000001
    assert hight.evaluate([plaintext, key], verbosity=False) == 0x2b8b6b285d2d0e9c

    hight = HightBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=32)
    assert hight.evaluate([plaintext, key], verbosity=False) == 0x3b25d694326c4375
