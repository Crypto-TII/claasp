from claasp.ciphers.permutations.subterranean_permutation import SubterraneanPermutation, Version

import pytest

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

TEST_VECTORS_V2 = [
    (
        0x0,
        0x13557e25a50924bc7bc379ae1c74744952c2bda65110bf521bd1e19a786bf6598
    ),
    (
        0x10000000000000000000000000000000000000000000000000000000000000000,
        0x1d2ecfe9d4ef2e340caa94592592683edccd2028e93dd5f0393852b100f6e003d
    ),
    (
        0x8000000000000000000000000000000000000000000000000000000000000000,
        0xe3906013f82f0594c3aaa0dafc50ff643681e82b2e1eb2437ae77baf0d8b06d6
    ),
    (
        0x1,
        0x12e4ea1fd3cb43a85fd963433573c9ef1fb893ade455fbc0e098e76c125c2d442
    ),
    (
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
        0xc1b90e7e1606436f370cc9f13debe426d1511bdee835ac7a717976a83261c6fa
    ),
    (
        0x41016725d5847b43a3974f20bcda926608b3e1004cb1f185640e97e4480875b9,
        0xeffa7128ff593ecb6d9e0d5bfac806d1ce7b77889a9eaa7aa88beb0dd2fea12b
    )
]


def test_subterranean_output_size():
    st = SubterraneanPermutation()
    assert st.output_bit_size == 257


@pytest.mark.parametrize('pt,key,rounds,expected', TEST_VECTORS)
def test_subterranean_permutation(pt, key, rounds, expected):
    """Test vectors from a custom implementation of [CDGP1993]_."""

    subt = SubterraneanPermutation(number_of_rounds=rounds)
    ct = subt.evaluate([pt, key])
    assert ct == expected


@pytest.mark.parametrize('pt,expected', TEST_VECTORS_V2)
def test_subterranean_v2_permutation(pt, expected):
    """Test vectors generated from official implementation [NISTLWCSUB]_."""

    st = SubterraneanPermutation(version=Version.V2, number_of_rounds=5)
    ct = st.evaluate([pt])
    assert ct == expected
