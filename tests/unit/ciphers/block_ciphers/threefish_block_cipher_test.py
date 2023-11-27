from claasp.ciphers.block_ciphers.threefish_block_cipher import ThreefishBlockCipher


def test_threefish_block_cipher():
    threefish = ThreefishBlockCipher()
    assert threefish.type == 'block_cipher'
    assert threefish.family_name == 'threefish'
    assert threefish.number_of_rounds == 72
    assert threefish.id == 'threefish_p256_k256_t128_o256_r72'
    assert threefish.component_from(0, 0).id == 'constant_0_0'

    threefish = ThreefishBlockCipher(number_of_rounds=4)
    assert threefish.number_of_rounds == 4
    assert threefish.id == 'threefish_p256_k256_t128_o256_r4'
    assert threefish.component_from(3, 0).id == 'modadd_3_0'

    threefish = ThreefishBlockCipher()
    plaintext = 0x0
    key = 0x0
    tweak = 0x0
    ciphertext = 0x94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11
    assert threefish.evaluate([plaintext, key, tweak]) == ciphertext

    plaintext = 0xF8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7
    key = 0x17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A2928
    tweak = 0x07060504030201000F0E0D0C0B0A0908
    ciphertext = 0xDF8FEA0EFF91D0E0D50AD82EE69281C976F48D58085D869DDF975E95B5567065
    assert threefish.evaluate([plaintext, key, tweak]) == ciphertext
    assert threefish.test_against_reference_code(2) is True

    threefish = ThreefishBlockCipher(block_bit_size=512, key_bit_size=512)
    plaintext = 0x0
    key = 0x0
    tweak = 0x0
    ciphertext = int('0xBC2560EFC6BBA2B1E3361F162238EB40FB8631EE0ABBD1757B9479D4C5479ED1CFF0356E58F8C27BB1B7B08430F'
                     '0E7F7E9A380A56139ABF1BE7B6D4AA11EB47E', 16)
    assert threefish.evaluate([plaintext, key, tweak]) == ciphertext

    plaintext = int('0xF8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7D8D9DADBDCDDDEDFD0D1D2D3D4D5'
                    'D6D7C8C9CACBCCCDCECFC0C1C2C3C4C5C6C7', 16)
    key = int('0x17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A292837363534333231303F3E3D3C3B3A393847'
              '464544434241404F4E4D4C4B4A4948', 16)
    tweak = 0x07060504030201000F0E0D0C0B0A0908
    ciphertext = int('0x2C5AD426964304E39A2436D6D8CA01B4DD456DB00E333863794725970EB9368B043546998D0A2A2725A7C918EA2'
                     '04478346201A1FEDF11AF3DAF1C5C3D672789', 16)
    assert threefish.evaluate([plaintext, key, tweak]) == ciphertext
    assert threefish.test_against_reference_code(2) is True
