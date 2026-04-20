from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher


def test_katan_block_cipher():
    """
    Official test vectors for the KATAN block cipher are not available.
    The following test vectors were generated from the implementation provided in:
    https://gist.github.com/raullenchai/2662701
    https://gist.github.com/raullenchai/2712516
    """
    katan = KatanBlockCipher()
    assert katan.type == 'block_cipher'
    assert katan.family_name == 'katan'
    assert katan.number_of_rounds == 254
    assert katan.id == 'katan_p32_k80_o32_r254'

    katan = KatanBlockCipher(block_bit_size=48, number_of_rounds=4)
    assert katan.number_of_rounds == 4
    assert katan.id == 'katan_p48_k80_o48_r4'

    key = 0xFFFFFFFFFFFFFFFFFFFF
    plaintext = 0x00000000

    assert KatanBlockCipher().evaluate([plaintext, key]) == 0x7E1FF945
    assert KatanBlockCipher(block_bit_size=48).evaluate([plaintext, key]) == 0x4B7EFCFB8659
    assert KatanBlockCipher(block_bit_size=64).evaluate([plaintext, key]) == 0x21F2E99C0FAB828A

    key = 0x0123456789ABCDEFFEDC
    assert KatanBlockCipher().evaluate([0x12345678, key]) == 0xCFFDC7DA
    assert KatanBlockCipher(block_bit_size=48).evaluate([0x123456789ABC, key]) == 0x0675F0F5DA84
    assert KatanBlockCipher(block_bit_size=64).evaluate([0x123456789ABCDEF0, key]) == 0x0B3EDCA9A41D4619