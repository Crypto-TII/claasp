from claasp.ciphers.permutations.ascon_permutation import AsconPermutation


def test_ascon_permutation():
    ascon = AsconPermutation()
    assert ascon.family_name == 'ascon'
    assert ascon.type == 'permutation'
    assert ascon.number_of_rounds == 12
    assert ascon.id == 'ascon_p320_o320_r12'
    assert ascon.component_from(0, 0).id == 'constant_0_0'

    ascon = AsconPermutation(number_of_rounds=4)
    assert ascon.number_of_rounds == 4
    assert ascon.id == 'ascon_p320_o320_r4'
    assert ascon.component_from(3, 0).id == 'constant_3_0'


def test_ascon_permutation_official_reference_vectors():
    """Check vectors generated with the Ascon team's NIST SP 800-232 reference implementation.

    The vectors use ``ascon-c`` commit 446347f21b209f3921c65ece70027c366cbe1693 [ASCONREF]_. CLAASP represents
    the state as the concatenation ``x0 || x1 || x2 || x3 || x4`` of five 64-bit word values. This is distinct from
    the little-endian byte serialization used at the external interfaces of the standardized algorithms.
    """
    ascon = AsconPermutation(number_of_rounds=12)
    plaintext = 0x0
    ciphertext = 0x78ea7ae5cfebb1089b9bfb8513b560f76937f83e03d11a503fe53f36f2c1178c045d648e4def12c9
    assert ascon.evaluate([plaintext]) == ciphertext
    assert ascon.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
