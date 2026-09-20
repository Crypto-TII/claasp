"""Complete legacy wordwise domain/XOR/MDS abstraction evidence."""

import hashlib
from functools import reduce
from itertools import product

from claasp.semantics.cryptanalysis import (
    WordwiseDifferenceKind as Kind,
)
from claasp.semantics.cryptanalysis import (
    WordwiseXorDifference as Difference,
)
from claasp.semantics.cryptanalysis import (
    propagate_dense_wordwise_activity,
)


def _inputs(width):
    return (
        (Difference(width, Kind.ZERO),)
        + tuple(Difference.known(width, value) for value in range(1, 1 << width))
        + (Difference(width, Kind.NONZERO), Difference(width, Kind.UNKNOWN))
    )


def _encode(difference):
    return f"{difference.kind.value:02b}" + f"{difference.value or 0:0{difference.width}b}"


def _digest(rows):
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def test_all_18_wordwise_input_patterns_and_324_xor_rows():
    inputs = _inputs(4)
    patterns = tuple(map(_encode, inputs))
    assert len(patterns) == 18
    assert patterns[:2] == ("000000", "010001")
    assert patterns[-2:] == ("100000", "110000")
    rows = tuple(
        _encode(left) + _encode(right) + _encode(Difference.xor_many((left, right)))
        for left, right in product(inputs, repeat=2)
    )
    assert len(rows) == 324
    assert rows[:2] == ("000000000000000000", "000000010001010001")
    assert rows[-2:] == ("110000100000110000", "110000110000110000")
    assert _digest(patterns) == "26eceb4b17fa5ff6e68fd0d1e38876cfb708c388b0a4c834d78c93054bc385f6"
    assert _digest(rows) == "c5ea0af2f66bf9d67379e196151b12e9e6abc7717b10a3f5ed6c5b9531f94a39"

    # Independently enumerate concrete XOR values for every abstract pair.
    def concrete(item):
        return (
            {item.value}
            if item.kind in (Kind.ZERO, Kind.KNOWN)
            else set(range(1, 16))
            if item.kind is Kind.NONZERO
            else set(range(16))
        )

    for left, right in product(inputs, repeat=2):
        result = Difference.xor_many((left, right))
        actual = {a ^ b for a, b in product(concrete(left), concrete(right))}
        assert actual <= concrete(result)
        if len(actual) == 1:
            assert result.value == next(iter(actual))
        elif 0 not in actual:
            assert result.kind is Kind.NONZERO
        else:
            assert result.kind is Kind.UNKNOWN


def test_nary_xor_retains_nonzero_after_known_cancellation():
    assert (
        Difference.xor_many(
            (Difference(4, Kind.NONZERO), Difference.known(4, 7), Difference.known(4, 7))
        ).kind
        is Kind.NONZERO
    )
    inputs = _inputs(3)
    rows = tuple(
        "".join(map(_encode, items)) + _encode(Difference.xor_many(items))
        for items in product(inputs, repeat=3)
    )
    assert _digest(rows) == "9c8c0b98ef30e479dd55d4eecc4de2cd032fbbe108bcd4471e813da38de9d92e"
    fixed_cubes = (
        "0-000-0---00----1---",
        "0-00000----0----1---",
        "-----1---------0----",
        "1--------------0----",
    )
    assert all(
        not all(symbol == "-" or symbol == value for symbol, value in zip(cube, row))
        for cube in fixed_cubes
        for row in rows
    )


def test_all_256_dense_mds_activity_patterns_and_fixed_rows():
    rows = []
    for kinds in product(Kind, repeat=4):
        inputs = tuple(
            Difference.known(4, 1) if kind is Kind.KNOWN else Difference(4, kind) for kind in kinds
        )
        outputs = propagate_dense_wordwise_activity(inputs, 4)
        rows.append("".join(f"{item.kind.value:02b}" for item in inputs + outputs))
    assert len(rows) == 256
    assert rows[:2] == ["0000000000000000", "0000000110101010"]
    assert rows[-2:] == ["1111111011111111", "1111111111111111"]
    assert _digest(rows) == "5929ffb45fda743b713eca3c95fa042304523ce4252ee9774993b5ee3f7d55a8"


def test_fixed_wordwise_input_cubes_match_the_complete_typed_domain():
    patterns = set(map(_encode, _inputs(3)))
    cubes = ("01000", "-0--1", "1---1", "-0-1-", "1--1-", "-01--", "1-1--")
    for bits in product("01", repeat=5):
        row = "".join(bits)
        rejected = any(
            all(symbol == "-" or symbol == value for symbol, value in zip(cube, row))
            for cube in cubes
        )
        assert rejected is (row not in patterns)


def test_dense_activity_bound_is_sound_for_all_small_field_values():
    # GF(4), modulus x^2+x+1. A dense matrix, not assumed MDS.
    multiplication = ((0, 0, 0, 0), (0, 1, 2, 3), (0, 2, 3, 1), (0, 3, 1, 2))
    matrix = ((1, 2, 3, 1), (2, 3, 1, 2), (3, 1, 2, 3), (1, 3, 2, 1))

    def concrete(item):
        return (
            {item.value}
            if item.kind in (Kind.ZERO, Kind.KNOWN)
            else set(range(1, 4))
            if item.kind is Kind.NONZERO
            else set(range(4))
        )

    for kinds in product(Kind, repeat=4):
        inputs = tuple(
            Difference.known(2, 1) if kind is Kind.KNOWN else Difference(2, kind) for kind in kinds
        )
        outputs = propagate_dense_wordwise_activity(inputs, 4)
        for values in product(*(concrete(item) for item in inputs)):
            result = tuple(
                reduce(
                    int.__xor__,
                    (multiplication[coefficient][value] for coefficient, value in zip(row, values)),
                    0,
                )
                for row in matrix
            )
            assert all(value in concrete(item) for value, item in zip(result, outputs))
