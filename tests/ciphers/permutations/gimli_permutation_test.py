from claasp.ciphers.permutations.gimli_permutation import GimliPermutation


def test_gimli_permutation():
    gimli = GimliPermutation()
    assert gimli.family_name == 'gimli'
    assert gimli.type == 'permutation'
    assert gimli.number_of_rounds == 24
    assert gimli.WORD_BIT_SIZE == 32
    assert gimli.id == 'gimli_p384_o384_r24'
    assert gimli.component_from(0, 0).id == 'rot_0_0'

    gimli = GimliPermutation(number_of_rounds=4, word_size=32)
    assert gimli.number_of_rounds == 4
    assert gimli.id == 'gimli_p384_o384_r4'
    assert gimli.component_from(3, 0).id == 'rot_3_0'

    gimli = GimliPermutation(number_of_rounds=24)
    plaintext = 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    ciphertext = 0x23542ead7b4796b2f28d29382593c056a31cbc74638c3fe33a602d4b7af3b087d069ed07d0637f8b943d93d3ae1ab09b
    assert gimli.evaluate([plaintext]) == ciphertext

    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ciphertext = 0x6467d8c407dcf83b3b0bb0d41b21364c083431dc0efbbe8e0054e884648bd9554a5db42eca0641cb8673d2c22e30d809
    assert gimli.evaluate([plaintext]) == ciphertext

    plaintext = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    ciphertext = 0xe23a7f07594a8f3ea3eaea5efe5a5076b0bd6790fdb37c828fc55598e4b023541e51d96a9c3ee4c421d1320625fd1c05
    assert gimli.evaluate([plaintext]) == ciphertext

    plaintext = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    ciphertext = 0xdc47844969732d2a7ab0a2e342d24f0fce1d9f7cecb5d905ace0d57071b4277df1dd95870af7d267c631f47672fccafc
    assert gimli.evaluate([plaintext]) == ciphertext

    plaintext = 0x1af105601000043540540354354350550000000100000001000000010000000100000001000000010000000100000001
    ciphertext = 0x100e4c1d8774953fb2b3d6a5f2e1af9b3f0f3fb5e32cba39245f231bf280918e62126d745cfb6a0221cf7adeb3dee484
    assert gimli.evaluate([plaintext]) == ciphertext
