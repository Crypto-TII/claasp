from itertools import product

from claasp.primitives.toy_primitives.heys import HEYS_SBOX
from claasp.semantics.cryptanalysis import TruncatedXorDifference
from claasp.semantics.cryptanalysis._lookup_truncated import _truncated_lookup


def test_lookup_abstract_outputs_match_all_concrete_pairs_for_every_input_pattern():
    for symbols in product("01?", repeat=4):
        pattern = "".join(symbols)
        outputs = set()
        for x in range(16):
            for y in range(16):
                delta = f"{x ^ y:04b}"
                if all(a == "?" or a == b for a, b in zip(pattern, delta)):
                    outputs.add(HEYS_SBOX[x] ^ HEYS_SBOX[y])
        expected = "".join(
            str(next(iter(bits)))
            if len(bits := {(value >> shift) & 1 for value in outputs}) == 1
            else "?"
            for shift in reversed(range(4))
        )
        assert (
            str(_truncated_lookup(HEYS_SBOX, TruncatedXorDifference.parse(pattern), 4)) == expected
        )
