from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation


def test_chaskeypi_permutation():
    chaskeypi = ChaskeyPiPermutation()

    assert chaskeypi.family_name == "chaskeypi_permutation"
    assert chaskeypi.type == "permutation"
    assert chaskeypi.number_of_rounds == 12
    assert chaskeypi.id == "chaskeypi_permutation_p128_o128_r12"
    assert chaskeypi.evaluate([0], verbosity=False) == 0


def test_chaskeypi_permutation_reduced_and_custom_parameters():
    reduced = ChaskeyPiPermutation(number_of_rounds=4, word_size=16)
    assert reduced.id == "chaskeypi_permutation_p64_o64_r4"
    assert reduced.evaluate([0], verbosity=False) == 0

    wide_state = ChaskeyPiPermutation(number_of_rounds=1, word_size=64)
    assert wide_state.id == "chaskeypi_permutation_p256_o256_r1"
    assert wide_state.evaluate([0], verbosity=False) == 0


def test_chaskeypi_permutation_derived_reference_vectors():
    """
    The vectors were derived from the Chaskey-12 reference implementation because
    standalone Chaskey-Pi permutation input/output vectors are not explicitly
    listed in the original source.

    REFERENCES:

    - Nicky Mouha, Chaskey-12 reference implementation:
      https://mouha.be/wp-content/uploads/chaskey12.c
    - Derivation notes and resulting vectors used here:
      playground/claasp/chaskey/chaskeypi_test_vectors.txt
    """

    chaskeypi = ChaskeyPiPermutation(number_of_rounds=12, word_size=32)

    vectors = [
        (
            0xFFAA5488AAFF00545500FFA90055AAFE,
            0x85907B5488DCD7C66F8681CE3FA86995,
        ),
        (
            0x566432879EACFAC8C7F5A3900F3D6B59,
            0xB1341B56BEEF313694054E3211A48DA3,
        ),
    ]

    for permutation_input, expected_output in vectors:
        assert chaskeypi.evaluate([permutation_input], verbosity=False) == expected_output