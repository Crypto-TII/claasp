from claasp.ciphers.permutations.gaston_permutation import GastonPermutation


def test_gaston_permutation():
    gaston = GastonPermutation(number_of_rounds=12)
    assert gaston.number_of_rounds == 12

    assert gaston.component_from(0, 0).id == 'rot_0_0'


def test_gaston_permutation_reference_vector():
    """Check an all-zero vector generated with the reference implementation linked by [GASTON2023]_.

    CLAASP concatenates the five 64-bit Gaston row values from most to least significant. The resulting integer is
    therefore the per-word byte reversal of a little-endian byte dump of the same state.
    """
    gaston = GastonPermutation(number_of_rounds=12)
    plaintext = 0
    ciphertext = 0x88B326096BEBC6356CA8FB64BC5CE6CAF1CE3840D819071354D70067438689B5F17FE863F958F32B
    assert gaston.evaluate([plaintext]) == ciphertext
    assert gaston.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
