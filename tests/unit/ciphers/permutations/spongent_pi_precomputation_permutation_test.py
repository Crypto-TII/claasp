from claasp.ciphers.permutations.spongent_pi_precomputation_permutation import SpongentPiPrecomputationPermutation


def test_spongent_pi_precomputation_permutation():
    spongentpi = SpongentPiPrecomputationPermutation()
    assert spongentpi.family_name == 'spongent_pi_precomputation'
    assert spongentpi.type == 'permutation'
    assert spongentpi.number_of_rounds == 80
    assert spongentpi.id == 'spongent_pi_precomputation_p160_o160_r80'
    assert spongentpi.component_from(0, 0).id == 'constant_0_0'

    spongentpi = SpongentPiPrecomputationPermutation(state_bit_size=160, number_of_rounds=4)
    assert spongentpi.number_of_rounds == 4
    assert spongentpi.id == 'spongent_pi_precomputation_p160_o160_r4'
    assert spongentpi.component_from(3, 0).id == 'constant_3_0'

    # Very long test
    plaintext = 0x0000000000000000000000000000000000000000
    ciphertext = 0x60a224efe52f9f1febbfe51f7a2dc9564341167
    assert spongentpi.evaluate([plaintext]) == ciphertext

    # Very long test
    spongentpi = SpongentPiPrecomputationPermutation(state_bit_size=176, number_of_rounds=4)
    plaintext = 0x0123456789abcdef0123456789abcdef0123456789ab
    ciphertext = 0x8675478f97cafe723bf668c5e573ae9b582131499660
    assert spongentpi.evaluate([plaintext]) == ciphertext
    assert spongentpi.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
