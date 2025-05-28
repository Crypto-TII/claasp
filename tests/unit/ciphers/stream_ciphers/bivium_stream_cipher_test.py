from claasp.ciphers.stream_ciphers.bivium_stream_cipher import BiviumStreamCipher


def test_bivium_stream_cipher_test_vector():
    biv = BiviumStreamCipher(keystream_bit_len=2 ** 2)
    key = 0xffffffffffffffffffff
    iv = 0xffffffffffffffffffff
    ks = 0x3
    assert biv.evaluate([key, iv]) == ks

