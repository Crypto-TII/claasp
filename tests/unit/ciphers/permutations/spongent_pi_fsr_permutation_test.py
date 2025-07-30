from claasp.ciphers.permutations.spongent_pi_fsr_permutation import SpongentPiFSRPermutation


def test_spongent_pi_fsr_permutation():
    spongentpi = SpongentPiFSRPermutation(state_bit_size=160, number_of_rounds=4)
    assert spongentpi.number_of_rounds == 4
    assert spongentpi.id == 'spongent_pi_fsr_p160_o160_r4'
    assert spongentpi.component_from(3, 0).id == 'fsr_3_0'

    # Very long test
    plaintext = 0x0000000000000000000000000000000000000000
    ciphertext = 0x60a224efe52f9f1febbfe51f7a2dc9564341167
    assert spongentpi.evaluate([plaintext]) == ciphertext

    # Very long test
    spongentpi = SpongentPiFSRPermutation(state_bit_size=176, number_of_rounds=4)
    plaintext = 0x0123456789abcdef0123456789abcdef0123456789ab
    ciphertext = 0x8675478f97cafe723bf668c5e573ae9b582131499660
    assert spongentpi.evaluate([plaintext]) == ciphertext
