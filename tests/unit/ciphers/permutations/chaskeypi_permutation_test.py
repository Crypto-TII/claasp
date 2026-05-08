"""Unit tests for ChaskeyPi permutation derived vectors.

REFERENCES:

Mouha, N. (2015). Chaskey: An Efficient MAC Algorithm for 32-Bit Microcontrollers.
 https://mouha.be/wp-content/uploads/chaskey12.c [Mouha2015]_.
"""

from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation


def test_chaskeypi_permutation_derived_reference_vectors():
    """Test permutation I/O vectors derived from [Mouha2015]_.

    Standalone Chaskey-Pi permutation input/output vectors are not explicitly
    listed in the original source; they were reconstructed from the published
    MAC reference vectors by treating each 128-bit message block as the
    permutation input and using the corresponding intermediate state after the
    12-round Chaskey-Pi permutation as the expected output.
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