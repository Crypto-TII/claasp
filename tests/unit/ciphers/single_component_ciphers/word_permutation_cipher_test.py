from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher


def test_word_permutation_cipher_smoke():
    cipher = WordPermutationCipher(word_size=2, number_of_words=2, permutation_description=[1, 0])
    out = cipher.evaluate([0b1010])
    assert cipher.type == "permutation"
    assert isinstance(out, int)


def test_word_permutation_cipher_default_description_rotates_words():
    cipher = WordPermutationCipher(word_size=2, number_of_words=4)

    assert cipher.evaluate([0b00_01_10_11]) == 0b01_10_11_00
