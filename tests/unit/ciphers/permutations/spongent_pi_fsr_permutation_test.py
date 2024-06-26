from claasp.ciphers.permutations.spongent_pi_fsr_permutation import SpongentPiFSRPermutation


def test_spongent_pi_fsr_permutation():
    spongentpi = SpongentPiFSRPermutation()
    assert spongentpi.family_name == 'spongent_pi_fsr'
    assert spongentpi.type == 'permutation'
    assert spongentpi.number_of_rounds == 80
    assert spongentpi.id == 'spongent_pi_fsr_p160_o160_r80'
    assert spongentpi.component_from(0, 0).id == 'constant_0_0'

    spongentpi = SpongentPiFSRPermutation(state_bit_size=160, number_of_rounds=4)
    assert spongentpi.number_of_rounds == 4
    assert spongentpi.id == 'spongent_pi_fsr_p160_o160_r4'
    assert spongentpi.component_from(3, 0).id == 'fsr_3_0'

    # Very long test
    spongentpi = SpongentPiFSRPermutation()
    plaintext = 0x0000000000000000000000000000000000000000
    ciphertext = 0xcaed745fb9d13ede0ec562a18682cba286000ce8
    assert spongentpi.evaluate([plaintext]) == ciphertext

    # Very long test
    spongentpi = SpongentPiFSRPermutation(state_bit_size=176, number_of_rounds=90)
    plaintext = 0x0123456789abcdef0123456789abcdef0123456789ab
    ciphertext = 0x04adf4b51546dc10694325ff73b1352f141d8023da08
    assert spongentpi.evaluate([plaintext]) == ciphertext
    #assert spongentpi.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
