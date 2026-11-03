from claasp.ciphers.permutations.gimli_permutation import GimliPermutation


def test_gimli_permutation():
    gimli = GimliPermutation()
    assert gimli.family_name == 'gimli'
    assert gimli.type == 'permutation'
    assert gimli.number_of_rounds == 24
    assert gimli.word_bit_size == 32
    assert gimli.id == 'gimli_p384_o384_r24'
    assert gimli.component_from(0, 0).id == 'rot_0_0'

    gimli = GimliPermutation(number_of_rounds=4, word_size=32)
    assert gimli.number_of_rounds == 4
    assert gimli.id == 'gimli_p384_o384_r4'
    assert gimli.component_from(3, 0).id == 'rot_3_0'


def test_gimli_permutation_reference_vector():
    """Check the all-zero vector generated with the reference C implementation in [GIMLI2017]_.

    CLAASP concatenates the twelve 32-bit words from most to least significant. Each word value below is therefore
    the byte reversal of the corresponding four bytes in a little-endian state dump.
    """
    gimli = GimliPermutation(number_of_rounds=24)
    plaintext = 0
    ciphertext = 0x6467d8c407dcf83b3b0bb0d41b21364c083431dc0efbbe8e0054e884648bd9554a5db42eca0641cb8673d2c22e30d809
    assert gimli.evaluate([plaintext]) == ciphertext
    assert gimli.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
