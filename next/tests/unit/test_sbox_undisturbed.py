"""Every PRESENT undisturbed-bit fixture and an independent DDT join."""

from itertools import product

import pytest

from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX
from claasp_next.semantics.cryptanalysis import SBoxTransitionSemantics, TruncatedXorDifference
from claasp_next.representations.constraints.milp.relations import FiniteBinaryRelationMILPModel


def test_all_81_present_patterns_and_fixed_undisturbed_transitions():
    semantics = SBoxTransitionSemantics(PRESENT_SBOX)
    rows = []
    undisturbed = []
    for symbols in product("01?", repeat=4):
        pattern = TruncatedXorDifference.parse("".join(symbols))
        output = semantics.truncated_xor_differential(pattern)
        concrete = [value for value in range(16) if all(symbol == "?" or int(symbol) == ((value >> (3 - bit)) & 1)
                                                       for bit, symbol in enumerate(symbols))]
        possible = {beta for alpha in concrete for beta in range(16)
                    if semantics.xor_differential(alpha, beta).is_possible}
        expected = "".join(str(next(iter(bits))) if len(bits) == 1 else "?"
                           for bit in range(4) for bits in [{(value >> (3 - bit)) & 1 for value in possible}])
        assert str(output) == expected
        if str(output) != "????":
            undisturbed.append((tuple(bit.encoded for bit in pattern.bits), tuple(bit.encoded for bit in output.bits)))
        rows.append(tuple(bit for value in (*pattern.bits, *output.bits) for bit in (value.encoded >> 1, value.encoded & 1)))
    assert len(rows) == 81
    assert undisturbed == [
        ((0, 0, 0, 0), (0, 0, 0, 0)),
        ((0, 0, 0, 1), (2, 2, 2, 1)),
        ((1, 0, 0, 0), (2, 2, 2, 1)),
        ((1, 0, 0, 1), (2, 2, 2, 0)),
    ]
    relation = FiniteBinaryRelationMILPModel(tuple(f"bit_{bit}" for bit in range(16)), rows)
    model = relation.milp_model()
    assert all(model.is_feasible(relation.witness(row)) for row in rows)
    cubes = ("------11-", "----11---", "--11-----", "11-------", "--------1")
    projected = [row[:8] + (row[9],) for row in rows]
    assert all(not all(symbol == "-" or int(symbol) == value for symbol, value in zip(cube, row))
               for cube in cubes for row in projected)


def test_undisturbed_patterns_require_matching_width():
    with pytest.raises(ValueError, match="width"):
        SBoxTransitionSemantics(PRESENT_SBOX).truncated_xor_differential(TruncatedXorDifference.parse("01"))
