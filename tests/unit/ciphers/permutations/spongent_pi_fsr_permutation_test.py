from claasp.ciphers.permutations.spongent_pi_fsr_permutation import SpongentPiFSRPermutation


def test_spongent_pi_fsr_permutation():
    spongentpi = SpongentPiFSRPermutation(state_bit_size=160, number_of_rounds=8)
    assert spongentpi.number_of_rounds == 8
    assert spongentpi.id == 'spongent_pi_fsr_p160_o160_r8'
    assert spongentpi.component_from(3, 0).id == 'fsr_3_0'
    plaintext = 0x0000000000000000000000000000000000000000
    ciphertext = 0x8ec029fbad1689d63bb43a488a58c957885d3d8a
    assert spongentpi.evaluate([plaintext]) == ciphertext
