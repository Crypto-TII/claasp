from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation


def test_keccak_invertible_permutation():
    keccak = KeccakInvertiblePermutation(number_of_rounds=2, word_size=64)
    assert keccak.number_of_rounds == 2
    assert keccak.id == 'keccak_invertible_p1600_o1600_r2'
    assert keccak.component_from(1, 0).id == 'theta_keccak_1_0'

    # Very long test
    keccak = KeccakInvertiblePermutation(number_of_rounds=1)
    plaintext = int('0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000', 16)
    ciphertext = int('0x000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000'
                     '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                     '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                     '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                     '0000000000000000000000', 16)
    assert keccak.evaluate([plaintext]) == ciphertext

    # Very long test
    plaintext = int('0xf1258f7940e1dde784d5ccf933c0478ad598261ea65aa9eebd1547306f80494d8b284e056253d057ff97a42d7f8e6f'
                    'd490fee5a0a44647c48c5bda0cd6192e76ad30a6f71b19059c30935ab7d08ffc64eb5aa93f2317d635a9a6e6260d7121'
                    '0381a57c16dbcf555f43b831cd0347c82601f22f1a11a5569f05e5635a21d9ae6164befef28cc970f2613670957bc466'
                    '11b87c5a554fd00ecb8c3ee88a1ccf32c8940c7922ae3a26141841f924a2c509e416f53526e70465c275f644e97f30a1'
                    '3beaf1ff7b5ceca249', 16)
    ciphertext = int('0x7da852fb04497b0a894ec24cdf6de92aff6e9cb2d9b82c205c8f5ef41367412f9e341a1d45dc7cb9754bd8010a687'
                     '5ae6bc9e3fde54d0d63680c01bc9e12e891efdcc728724da09aeaf79b1f5e8ebc41d7d9256e50e369d8f98dd4fb0055'
                     'ee825c090034935bf012b0cb7849e930b86534d6137db0b948f13de547bd2f116f9c22cfbb2cc488de1cabb64b90bfd'
                     '7f864d035e36e9f592fdbda0c4b9af7eb5a9ff16d4c4ee3b1c1aa41d32b6f26f9e4794d5bac33329974c93d9a2ac3f0'
                     '3d425e939397161e889b37', 16)
    assert keccak.evaluate([plaintext]) == ciphertext

    # # Very long test
    keccak = KeccakInvertiblePermutation(number_of_rounds=2)
    plaintext = int('0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000', 16)
    ciphertext = int('0x808300001000000000000000000000008000000000000000000100001000000080000000000000000000000020000'
                     '02000000000000000000000000020000000000000000000002000000000000000000002000000000000020000000000'
                     '00000000000000000000020200000000000000000000000010000400000000000000000000000000000004000000000'
                     '01000000000000000000000000000010000000000000000000000000000000100000000040000000000000000000000'
                     '0000000004', 16)
    assert keccak.evaluate([plaintext]) == ciphertext
    assert keccak.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
