from claasp.ciphers.permutations.subterranean_permutation import SubterraneanPermutation

TEST_VECTORS = [
    ((1 << 257) - 1, 0, 1,
     0x10000000000000001000008000000000000000000000000000000000000000000),

    (0, (1 << 256) - 1, 1,
     0x1000008000000000000000000000000000000000000000000),

    ((1 << 257) - 1, (1 << 256) - 1, 1,
     0x1fffffffffffffffefffff7ffffffffffffffffffffffffffffffffffffffffff),

    (0b1101010100101, 0b0101010101010100, 1,
     0xffffffffffffffffffffffffff9ffffcffffe7ffff9ffffcfffff7ffffdfffff),

    (0b1101010100101, 0b0101010101010100, 3,
     0x1566bc0e7c649fd3dae7a738a33694f5a991836ea819a6d74c999e5c6e7e5e667),
]


def test_subterranean_permutation():
    """Test vectors from a custom implementation of [CDGP1993]_."""

    st = SubterraneanPermutation()
    assert st.output_bit_size == 257

    for pt, key, rounds, expected in TEST_VECTORS:
        subt = SubterraneanPermutation(number_of_rounds=rounds)
        ct = subt.evaluate([pt, key])
        assert ct == expected
