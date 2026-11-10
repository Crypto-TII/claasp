"""Concrete containment checks independent of the SAT encoding."""

from itertools import product
from operator import add, and_, or_, sub

import pytest

from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference
from claasp.semantics.cryptanalysis._wordwise_operations import _boolean, _modular, _pack, _unpack


def _values(difference):
    if difference.kind in (Kind.ZERO, Kind.KNOWN):
        return (difference.value,)
    return range(int(difference.kind is Kind.NONZERO), 1 << difference.width)


@pytest.mark.parametrize("width", (1, 2, 3))
@pytest.mark.parametrize(
    "operation,transfer", ((add, _modular), (sub, _modular), (and_, _boolean), (or_, _boolean))
)
def test_elementary_transfers_contain_every_concrete_pair(width, operation, transfer):
    mask = (1 << width) - 1
    abstract = (
        Difference(width, Kind.ZERO),
        Difference(width, Kind.NONZERO),
        Difference(width, Kind.UNKNOWN),
        *(Difference.known(width, value) for value in range(1, mask + 1)),
    )
    for left, right in product(abstract, repeat=2):
        result = transfer((left, right))
        allowed = set(_values(result))
        for dl, dr in product(_values(left), _values(right)):
            for x, y in product(range(mask + 1), repeat=2):
                delta = (operation(x, y) & mask) ^ (operation(x ^ dl, y ^ dr) & mask)
                assert delta in allowed, (left, right, x, y, delta, result)


def test_modular_transfer_does_not_assume_known_carry_behavior():
    known = Difference.known(3, 1)
    zero = Difference(3, Kind.ZERO)
    assert _modular((known, zero)).kind is Kind.NONZERO
    assert _modular((known, known)).kind is Kind.UNKNOWN
    assert _modular((zero, zero)).kind is Kind.ZERO


@pytest.mark.parametrize("width", (1, 2, 3))
def test_pack_unpack_containment_and_msb_order(width):
    abstract_bits = (
        Difference(1, Kind.ZERO),
        Difference.known(1, 1),
        Difference(1, Kind.NONZERO),
        Difference(1, Kind.UNKNOWN),
    )
    for bits in product(abstract_bits, repeat=width):
        packed = _pack(bits, width)
        for values in product(*(_values(bit) for bit in bits)):
            value = sum(bit << (width - 1 - i) for i, bit in enumerate(values))
            assert value in _values(packed)
        unpacked = _unpack(packed, width)
        for value in _values(packed):
            assert all(
                (value >> (width - 1 - i)) & 1 in _values(bit) for i, bit in enumerate(unpacked)
            )
    known = Difference.known(width, 1 << (width - 1))
    assert _pack(_unpack(known, width), width) == known


def test_conversion_width_mismatches_fail():
    with pytest.raises(ValueError, match="width-one"):
        _pack((Difference(2, Kind.ZERO),), 1)
    with pytest.raises(ValueError, match="match"):
        _unpack(Difference(2, Kind.ZERO), 1)
