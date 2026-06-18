"""Standalone validation for the Phase 3 value-class model.

Confirms the union-find ``ValueClasses`` faithfully captures - and transitively completes - the
engine's own static equivalence relation (``get_all_equivalent_bits``). Fast: no inversion is
run, this only inspects the static relation. The behavioural gate
(``inverse_regression_test.py``) remains the oracle for anything that touches the live engine.
"""

import pytest

from claasp.cipher_modules.inverse.equivalence import get_all_equivalent_bits
from claasp.cipher_modules.inverse.value_model import UnionFind, ValueClasses
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher

_CIPHERS = [
    ("speck", lambda: SpeckBlockCipher(number_of_rounds=3)),
    ("ublock", lambda: UblockBlockCipher(number_of_rounds=2)),
]


def test_union_find_basic():
    uf = UnionFind()
    uf.union("a", "b")
    uf.union("b", "c")
    assert uf.same("a", "c")
    assert uf.find("a") == uf.find("c")
    assert not uf.same("a", "d")
    # unknown keys are self-roots
    assert uf.find("z") == "z"


@pytest.mark.parametrize("name,build", _CIPHERS, ids=[c[0] for c in _CIPHERS])
def test_value_classes_capture_static_relation(name, build):
    cipher = build()
    equivalences = get_all_equivalent_bits(cipher)
    classes = ValueClasses(cipher)
    # Every directly-related pair must land in the same value class.
    for bit_name, neighbours in equivalences.items():
        for neighbour in neighbours:
            assert classes.same(bit_name, neighbour), f"{bit_name} !~ {neighbour}"


@pytest.mark.parametrize("name,build", _CIPHERS, ids=[c[0] for c in _CIPHERS])
def test_value_classes_are_transitively_closed(name, build):
    cipher = build()
    equivalences = get_all_equivalent_bits(cipher)
    classes = ValueClasses(cipher)
    # If a~b and b~c are both present in the (non-closed) adjacency map, the union-find must
    # also relate a~c - the closure the engine otherwise computes by walking the map.
    for bit_name, neighbours in equivalences.items():
        for neighbour in neighbours:
            for second_hop in equivalences.get(neighbour, []):
                assert classes.same(bit_name, second_hop)
