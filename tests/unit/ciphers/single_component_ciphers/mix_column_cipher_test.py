from claasp.ciphers.single_component_ciphers.mix_column_cipher import MixColumnCipher


def test_mix_column_cipher_smoke():
    cipher = MixColumnCipher(word_size=4, number_of_words=4)
    out = cipher.evaluate([0xABCD])
    assert cipher.type == "hash_function"
    assert isinstance(out, int)
