from claasp.ciphers.stream_ciphers.zuc_stream_cipher import ZucStreamCipher


def test_zuc_stream_cipher_test_vector():
    zuc = ZucStreamCipher(len_keystream_word=2)
    iv = 0xffffffffffffffffffffffffffffffff
    key = 0xffffffffffffffffffffffffffffffff
    ks = 0x657cfa07096398b
    assert zuc.evaluate([key, iv]) == ks
