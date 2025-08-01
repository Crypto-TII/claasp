from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher


def test_trivium_stream_cipher_test_vector():
    triv = TriviumStreamCipher(keystream_bit_len=256)
    key = 0x00000000000000000000
    iv = 0x00000000000000000000
    ks = 0xdf07fd641a9aa0d88a5e7472c4f993fe6a4cc06898e0f3b4e7159ef0854d97b3
    assert triv.evaluate([key, iv]) == ks