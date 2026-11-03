from claasp.ciphers.permutations.knot_permutation import KnotPermutation


def test_knot_permutation():
    knot = KnotPermutation()
    assert knot.family_name == "knot"
    assert knot.type == "permutation"
    assert knot.number_of_rounds == 52
    assert knot.id == "knot_p256_o256_r52"
    assert knot.component_from(0, 0).id == "constant_0_0"

    knot = KnotPermutation(state_bit_size=384)
    assert knot.number_of_rounds == 76
    assert knot.id == "knot_p384_o384_r76"

    knot = KnotPermutation(state_bit_size=512)
    assert knot.number_of_rounds == 100
    assert knot.id == "knot_p512_o512_r100"

    knot = KnotPermutation(state_bit_size=256, number_of_rounds=7)
    assert knot.number_of_rounds == 7
    assert knot.id == "knot_p256_o256_r7"
    assert knot.component_from(6, 0).id == "constant_6_0"


def test_knot_permutation_reference_vectors():
    """Check vectors generated with the KNOT team's reference implementation [ZDY+2019]_.

    The three ``(plaintext, ciphertext)`` pairs are the full-round permutation ``p_b[nr_0]`` applied to a
    pseudo-random state, one per state width (``b = 256, 384, 512`` with ``nr_0 = 52, 76, 100`` and the LFSR
    degree ``d = 6, 7, 7`` of the matching KNOT-AEAD member). They were produced by an independent bit-level
    transcription of the KNOT v1 specification, Section 2, that reproduces the official KNOT-Hash Known Answer
    Test digests for every state width. ``plaintext`` and ``ciphertext`` are the specification state
    ``W = w_{b-1} || ... || w_0`` read as a big-endian integer, so ``a_{i,j} = w_{i * (b / 4) + j}`` has
    integer weight ``2 ** (i * (b / 4) + j)``.
    """
    knot256 = KnotPermutation(state_bit_size=256)
    plaintext = 0x70CA5295ADDD465EC7A6E65D18E52FCF641272D4AEA536C6FA27FB53DEA8EC4B
    ciphertext = 0xE0E6A438C31EA69D6E026B481B07C3FEFA4FA965CE69C36BED4B48F1CD38AA68
    assert knot256.evaluate([plaintext]) == ciphertext
    assert knot256.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext

    knot384 = KnotPermutation(state_bit_size=384)
    plaintext = 0x270323CE8A5B5073B70A53F9B02D7F275AC40CEAD8ABCCF9D8D67514255AB0AB6537EF3B420451C9E76D77E4C011CFB5
    ciphertext = 0x21C33F85099813D2BF776F1215323D1D655881760834C2AA0933F6ED907158670A5834543366CC19755DD1BDCF91D04A
    assert knot384.evaluate([plaintext]) == ciphertext
    assert knot384.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext

    knot512 = KnotPermutation(state_bit_size=512, bit_slice=True)
    plaintext = 0x8E36D773DEE2EB3B74CE68707F2FAE1165FACB31785C9DD0C17037FB199E2E46A3F06DEB56CABAC170AB4CE5B4586C5C7FB3926B46FDC6B3EB0889213FE71291
    ciphertext = 0x8E5CDC2BCBEAC1DC588D2177CEC557080279E0C799CD2B71C44ECC8D34374D11732F253A6C5611B090334869161C71F53ACB1D7AF06BD940D7E78D4FDD8FFD14
    assert knot512.evaluate([plaintext]) == ciphertext
    assert knot512.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
