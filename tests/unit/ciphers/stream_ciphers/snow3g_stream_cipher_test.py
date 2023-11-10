from claasp.ciphers.stream_ciphers.snow3g_stream_cipher import Snow3GStreamCipher


def test_snow3g_stream_cipher_test_vector():

    snow = Snow3GStreamCipher(number_of_initialization_clocks=2, keystream_word_size=2)
    iv = 0xEA024714AD5C4D84DF1F9B251C0BF45F
    key = 0x2BD6459F82C5B300952C49104881FF48
    ks_32 = 0xABEE97047AC31373 # keystream for full initialization rounds, i.e. 32
    ks2 = 10407660024169345926
    assert snow.evaluate([key, iv]) == ks2
