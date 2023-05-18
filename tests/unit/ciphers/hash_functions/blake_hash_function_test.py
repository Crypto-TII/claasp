from claasp.ciphers.hash_functions.blake_hash_function import BlakeHashFunction


def test_blake_hash_function():
    blake = BlakeHashFunction()
    assert blake.number_of_rounds == 28
    assert blake.type == 'hash_function'
    assert blake.family_name == 'blake'
    assert blake.id == 'blake_p512_i512_o512_r28'
    assert blake.component_from(0, 0).id == 'constant_0_0'

    blake = BlakeHashFunction(number_of_rounds=4)
    assert blake.number_of_rounds == 4
    assert blake.type == 'hash_function'
    assert blake.id == 'blake_p512_i512_o512_r4'
    assert blake.component_from(3, 0).id == 'constant_3_0'

    blake = BlakeHashFunction()
    plaintext = int('0x0080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000010000000000000008', 16)
    state = int('0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19243f6a8885a308d313198a2e03707344a4'
                '09382a299f31d8082efa98ec4e6c89', 16)
    output_state = int('0x7a07e5194c7e2bac28acf9eca5adb385f201e16106b69682b290a439232a09561ce6d791bace48a4761dd447d40'
                       'ff618d7a1d95f0f298ad48e03e31d69d958c8', 16)
    assert blake.evaluate([plaintext, state]) == output_state
    assert blake.test_against_reference_code(2) is True

    blake = BlakeHashFunction(block_bit_size=1024, state_bit_size=1024, word_size=64)
    plaintext = int('0x0080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000100000000000000000000000000000008', 16)
    state = int('0x6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f'
                '83d9abfb41bd6b5be0cd19137e2179243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821'
                'e638d0137fbe5466cf34e90c64c0ac29b7c97c50dd3f84d5b5b5470917', 16)
    output_state = int('0xa4c49432d99d5e8de90f2891abd6b4a649c0415e4a303c040411becca4309ea7d84c660093c4cabd1da7328a685'
                       'c8535af04db28c411cfe1148facbcaf9cd9fe595b67d2dcf8e77fe805a26c2b41f54c8f13bb9aae41cd1da413194a'
                       'd2feb3b276d336c6c8bc63d13e99bb3b08feef23aed8a237b480f33c7b6aea4550ab4634', 16)
    assert blake.evaluate([plaintext, state]) == output_state
    assert blake.test_against_reference_code(2) is True
