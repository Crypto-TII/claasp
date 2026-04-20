from claasp.ciphers.block_ciphers.ktantan_block_cipher import KtantanBlockCipher


def test_ktantan_block_cipher():
    """
    Official test vectors for the KTANTAN block cipher are not available.
    The following test vectors were generated from the implementation provided in:
    https://gist.github.com/raullenchai/2662701
    https://gist.github.com/raullenchai/2712516
    """
    ktantan = KtantanBlockCipher()
    assert ktantan.type == 'block_cipher'
    assert ktantan.family_name == 'ktantan'
    assert ktantan.number_of_rounds == 254
    assert ktantan.id == 'ktantan_p32_k80_o32_r254'

    ktantan = KtantanBlockCipher(block_bit_size=64, number_of_rounds=8)
    assert ktantan.number_of_rounds == 8
    assert ktantan.id == 'ktantan_p64_k80_o64_r8'

    key = 0xFFFFFFFFFFFFFFFFFFFF
    plaintext = 0x00000000

    assert KtantanBlockCipher().evaluate([plaintext, key]) == 0x22EA3988
    assert KtantanBlockCipher(block_bit_size=48).evaluate([plaintext, key]) == 0x936D0FA33A05
    assert KtantanBlockCipher(block_bit_size=64).evaluate([plaintext, key]) == 0xC02DE05BFA194B16

    key = 0x0123456789ABCDEFFEDC
    assert KtantanBlockCipher().evaluate([0x12345678, key]) == 0xB3F16EA2
    assert KtantanBlockCipher(block_bit_size=48).evaluate([0x123456789ABC, key]) == 0xEC5D5700FD6A
    assert KtantanBlockCipher(block_bit_size=64).evaluate([0x123456789ABCDEF0, key]) == 0xD2E6ABB1BDBCB6CC
