from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher


def test_trivium_stream_cipher_test_vector():
    triv = TriviumStreamCipher(keystream_bit_len=8)
    key = 0x00000000000000000000
    iv = 0x00000000000000000000
    ks = 0xdf
    assert triv.evaluate([key, iv]) == ks
