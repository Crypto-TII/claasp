from claasp.ciphers.block_ciphers.gift_sbox_block_cipher import GiftSboxBlockCipher


GIFT_64_TEST_VECTORS = [
    (0x0000000000000000, 0x00000000000000000000000000000000, 0xF62BC3EF34F775AC),
    (0xFEDCBA9876543210, 0xFEDCBA9876543210FEDCBA9876543210, 0xC1B71F66160FF587),
    (0xC450C7727A9B8A7D, 0xBD91731EB6BC2713A1F9F6FFC75044E7, 0xE3272885FA94BA8B),
]
GIFT_128_TEST_VECTORS = [
    (0x00000000000000000000000000000000, 0x00000000000000000000000000000000,
     0xCD0BD738388AD3F668B15A36CEB6FF92),
    (0xFEDCBA9876543210FEDCBA9876543210, 0xFEDCBA9876543210FEDCBA9876543210,
     0x8422241A6DBF5A9346AF468409EE0152),
    (0xE39C141FA57DBA43F08A85B6A91F86C1, 0xD0F5C59A7700D3E799028FA9F90AD837,
     0x13EDE67CBDCC3DBF400A62D6977265EA),
]


def test_gift_sbox_block_cipher():
    gift = GiftSboxBlockCipher()
    assert gift.family_name == 'gift_sbox'
    assert gift.type == 'block_cipher'
    assert gift.number_of_rounds == 40
    assert gift.id == 'gift_sbox_p128_k128_o128_r40'
    assert gift.component_from(0, 0).id == 'sbox_0_0'

    gift = GiftSboxBlockCipher(number_of_rounds=4)
    assert gift.number_of_rounds == 4
    assert gift.id == 'gift_sbox_p128_k128_o128_r4'
    assert gift.component_from(3, 0).id == 'rot_3_0'

    gift = GiftSboxBlockCipher()
    plaintext, key, ciphertext = GIFT_128_TEST_VECTORS[0]
    assert gift.evaluate([plaintext, key]) == ciphertext
    assert gift.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    input_list = [[plaintext, key] for plaintext, key, _ in GIFT_128_TEST_VECTORS]
    output_list = [ciphertext for _, _, ciphertext in GIFT_128_TEST_VECTORS]
    assert gift.test_vector_check(input_list, output_list)

    gift_64 = GiftSboxBlockCipher(block_bit_size=64)
    assert gift_64.number_of_rounds == 28
    assert gift_64.id == 'gift_sbox_p64_k128_o64_r28'
    plaintext, key, ciphertext = GIFT_64_TEST_VECTORS[0]
    assert gift_64.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    input_list = [[plaintext, key] for plaintext, key, _ in GIFT_64_TEST_VECTORS]
    output_list = [ciphertext for _, _, ciphertext in GIFT_64_TEST_VECTORS]
    assert gift_64.test_vector_check(input_list, output_list)
