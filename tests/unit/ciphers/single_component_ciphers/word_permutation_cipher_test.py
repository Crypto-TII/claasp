from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher


def test_word_permutation_cipher_smoke():
    cipher = WordPermutationCipher(word_size=2, number_of_words=2, permutation_description=[1, 0])
    out = cipher.evaluate([0b1010])
    assert cipher.type == "permutation"
    assert isinstance(out, int)
