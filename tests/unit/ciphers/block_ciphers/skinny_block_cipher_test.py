import pytest

from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_skinny_block_cipher():
    skinny = SkinnyBlockCipher()
    assert skinny.type == 'block_cipher'
    assert skinny.family_name == 'skinny'
    assert skinny.number_of_rounds == 40
    assert skinny.id == 'skinny_p128_k384_o128_r40'
    assert skinny.component_from(0, 0).id == 'constant_0_0'

    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=4)
    assert skinny.number_of_rounds == 4
    assert skinny.id == 'skinny_p128_k384_o128_r4'
    assert skinny.component_from(3, 0).id == 'rot_3_0'

    skinny = SkinnyBlockCipher(block_bit_size=128, key_bit_size=384, number_of_rounds=40)
    plaintext = 0x00000000000000000000000000000000
    key = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x4ced01d20a158953d0968f3a1ce190bc
    assert skinny.evaluate([plaintext, key]) == ciphertext

    plaintext = 0xa3994b66ad85a3459f44e92b08f550cb
    key = 0xdf889548cfc7ea52d296339301797449ab588a34a47f1ab2dfe9c8293fbea9a5ab1afac2611012cd8cef952618c3ebe8
    ciphertext = 0xff38d1d24c864c4352a853690fe36e5e
    assert skinny.evaluate([plaintext, key]) == ciphertext
