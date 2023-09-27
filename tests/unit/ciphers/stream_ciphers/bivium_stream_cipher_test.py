from claasp.ciphers.stream_ciphers.bivium_stream_cipher import BiviumStreamCipher


def test_bivium_stream_cipher_test_vector():
    biv = BiviumStreamCipher(keystream_bit_len=2 ** 8)
    key = 0xffffffffffffffffffff
    iv = 0xffffffffffffffffffff
    ks = 0x30d0e5ede563dee67884718977510a4c22661cf128d8f75af4a2708276014d83
    assert biv.evaluate([key, iv]) == ks
