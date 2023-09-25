from claasp.ciphers.permutations.gift_sbox_permutation import GiftSboxPermutation


def test_gift_sbox_permutation():
    gift = GiftSboxPermutation()
    assert gift.family_name == 'gift_sbox'
    assert gift.type == 'permutation'
    assert gift.number_of_rounds == 40
    assert gift.id == 'gift_sbox_p128_k128_o128_r40'
    assert gift.component_from(0, 0).id == 'sbox_0_0'

    gift = GiftSboxPermutation(number_of_rounds=4)
    assert gift.number_of_rounds == 4
    assert gift.id == 'gift_sbox_p128_k128_o128_r4'
    assert gift.component_from(3, 0).id == 'rot_3_0'

    gift = GiftSboxPermutation(number_of_rounds=40)
    key = 0x000102030405060708090A0B0C0D0E0F
    plaintext = 0x000102030405060708090A0B0C0D0E0F
    ciphertext = 0xA94AF7F9BA181DF9B2B00EB7DBFA93DF
    assert gift.evaluate([plaintext, key]) == ciphertext

    key1 = 0x000102030405060708090A0B0C0D0E0F
    plaintext1 = 0x000102030405060708090A0B0C0D0E0F
    ciphertext1 = 0xA94AF7F9BA181DF9B2B00EB7DBFA93DF
    key2 = 0xE0841F8FB90783136AA8B7F192F5C474
    plaintext2 = 0xE491C665522031CF033BF71B9989ECB3
    ciphertext2 = 0x3331EFC3A6604F9599ED42B7DBC02A38
    input_list = [[plaintext1, key1], [plaintext2, key2]]
    output_list = [ciphertext1, ciphertext2]
    assert gift.test_vector_check(input_list, output_list) is True
