"""Published vectors and independent-circuit checks for the research catalogue.

NOEKEON: designers' Noekeon_ref.zip/NoekeonTestVectors.txt.
PRIDE: Appendix J vectors, also reproduced in obfusk/pypride's examples.
uLBC: https://doi.org/10.62056/a63zzoja5, Appendix A (all six vectors).
"""

from random import Random

import pytest

from claasp.primitives import Noekeon


@pytest.mark.parametrize(
    "mode,p,k,c",
    [
        ("direct", 0, 0, 0xB1656851699E29FA24B70148503D2DFC),
        ("direct", (1 << 128) - 1, (1 << 128) - 1, 0x2A78421B87C7D0924F26113F1D1349B2),
        (
            "direct",
            0x2A78421B87C7D0924F26113F1D1349B2,
            0xB1656851699E29FA24B70148503D2DFC,
            0xE2F687E07B75660FFC372233BC47532C,
        ),
        ("indirect", 0, 0, 0xBA6933819299C71699A99F08F678178B),
        ("indirect", (1 << 128) - 1, (1 << 128) - 1, 0x52F88A7B283C1F7BDF7B6FAA5011C7D8),
        (
            "indirect",
            0x52F88A7B283C1F7BDF7B6FAA5011C7D8,
            0xBA6933819299C71699A99F08F678178B,
            0x5096F2BFC82AE6E2D9495515C277FA70,
        ),
    ],
)
def test_noekeon_designers_vectors(mode, p, k, c):
    assert Noekeon(key_mode=mode).evaluate(plaintext=p, key=k) == c


def _noekeon_circuit(p, k, rounds):
    """Specification's word-level Boolean gamma, independent of the S-box graph."""
    mask = (1 << 32) - 1

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    a = [(p >> (96 - 32 * i)) & mask for i in range(4)]
    key = [(k >> (96 - 32 * i)) & mask for i in range(4)]
    rc = 0x80

    def theta():
        t = a[0] ^ a[2]
        t ^= rol(t, 8) ^ rol(t, 24)
        a[1] ^= t
        a[3] ^= t
        for i in range(4):
            a[i] ^= key[i]
        t = a[1] ^ a[3]
        t ^= rol(t, 8) ^ rol(t, 24)
        a[0] ^= t
        a[2] ^= t

    for _ in range(rounds):
        a[0] ^= rc
        theta()
        for i, n in enumerate((1, 5, 2), 1):
            a[i] = rol(a[i], n)
        a[1] ^= (~a[3] & ~a[2]) & mask
        a[0] ^= a[2] & a[1]
        a[0], a[3] = a[3], a[0]
        a[2] ^= a[0] ^ a[1] ^ a[3]
        a[1] ^= (~a[3] & ~a[2]) & mask
        a[0] ^= a[2] & a[1]
        for i, n in enumerate((1, 5, 2), 1):
            a[i] = rol(a[i], 32 - n)
        rc = ((rc << 1) ^ (0x1B if rc & 128 else 0)) & 255
    a[0] ^= rc
    theta()
    return sum(v << (96 - 32 * i) for i, v in enumerate(a))


@pytest.mark.parametrize("rounds", [1, 2, 7, 16])
@pytest.mark.parametrize("mode", ["direct", "indirect"])
def test_noekeon_reduced_and_full_rounds_against_independent_boolean_circuit(rounds, mode):
    rng = Random(1607)
    primitive = Noekeon(rounds, key_mode=mode)
    for _ in range(4):
        p, k = rng.getrandbits(128), rng.getrandbits(128)
        working = _noekeon_circuit(k, 0, 16) if mode == "indirect" else k
        assert primitive.evaluate(plaintext=p, key=k) == _noekeon_circuit(p, working, rounds)
    assert len(primitive.graph.rounds) == rounds
