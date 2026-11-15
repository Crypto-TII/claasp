"""Structural SPN recognition, independently checked maps, and rejection cases."""

from dataclasses import FrozenInstanceError

import pytest

from claasp import Primitive, UnitArrayType
from claasp.analysis import DivisionPropertyPathSearch, SpnStructure
from claasp.components import BitVectorSBox, Identity, Xor
from claasp.graph import as_selection
from claasp.primitives import AES, Ascon, Keccak, Present, Speck
from claasp.unit_types import Bit


def test_aes_keys_are_excluded_and_final_standard_round_is_a_permutation():
    structure = SpnStructure(AES())
    assert structure.state_input == "plaintext"
    assert structure.state_size == structure.key_size == 128
    assert len(structure.substitution_layers) == 10
    assert all(len(layer.sboxes) == 16 for layer in structure.substitution_layers)
    assert [sum(map(sum, matrix)) for matrix in structure.linear_layers] == [736] * 9 + [128]
    assert all(sum(row) == 1 for row in structure.linear_layers[-1])
    attribute = "state_size"
    with pytest.raises(FrozenInstanceError):
        setattr(structure, attribute, 1)


def test_aes_first_map_is_shift_rows_then_mix_columns_independently():
    matrix = SpnStructure(AES(number_of_rounds=2)).linear_layers[0]

    def times_two(byte):
        return ((byte << 1) ^ (0x11B if byte & 128 else 0)) & 255

    def linear(value):
        state = [(value >> (8 * (15 - i))) & 255 for i in range(16)]
        shifted = [state[4 * ((column + row) % 4) + row] for column in range(4) for row in range(4)]
        result: list[int] = []
        for start in range(0, 16, 4):
            a, b, c, d = shifted[start : start + 4]
            result.extend(
                (
                    times_two(a) ^ times_two(b) ^ b ^ c ^ d,
                    a ^ times_two(b) ^ times_two(c) ^ c ^ d,
                    a ^ b ^ times_two(c) ^ times_two(d) ^ d,
                    times_two(a) ^ a ^ b ^ c ^ times_two(d),
                )
            )
        return tuple((byte >> bit) & 1 for byte in result for bit in range(7, -1, -1))

    for bit in range(128):
        assert tuple(row[bit] for row in matrix) == linear(1 << (127 - bit))


def test_keccak_chi_rows_match_the_five_bit_definition():
    structure = SpnStructure(Keccak(number_of_rounds=2, word_size=4))
    expected = []
    for value in range(32):
        bits = [(value >> (4 - i)) & 1 for i in range(5)]
        output = [bits[i] ^ ((1 ^ bits[(i + 1) % 5]) & bits[(i + 2) % 5]) for i in range(5)]
        expected.append(sum(bit << (4 - i) for i, bit in enumerate(output)))
    for layer in structure.substitution_layers:
        assert layer.kind == "chi" and len(layer.sboxes) == 20
        assert all(box.table == tuple(expected) for box in layer.sboxes)


@pytest.mark.parametrize(
    "primitive,expected",
    [
        (Ascon(number_of_rounds=2), "(5, 2, 64)-SPN"),
        (Keccak(number_of_rounds=2, word_size=4), "(5, 2, 20)-SPN"),
    ],
)
def test_chi_graphs_now_feed_division_property_search(primitive, expected):
    assert DivisionPropertyPathSearch(primitive).structure == expected


def _fixture(*, partial=False, cascade=False, bypass=False):
    primitive = Primitive("test_spn", {"plaintext": UnitArrayType(Bit(), (4,))})
    primitive._builder.add_round()
    state = primitive.graph.input("plaintext")
    source = state[:2] if partial else as_selection(state)
    table = (0, 1, 3, 2) if partial else tuple(x ^ ((x & 1) << 1) for x in range(16))
    output = primitive._builder.add_component(BitVectorSBox(source, table))
    if cascade:
        output = primitive._builder.add_component(BitVectorSBox(output, table))
    primitive._builder.add_round()
    output = primitive._builder.add_component(Identity(output))
    if bypass:
        output = primitive._builder.add_component(Xor((output, state)))
    primitive._builder.set_output(output)
    return primitive


@pytest.mark.parametrize(
    "options,match",
    [
        ({"partial": True}, "complete state"),
        ({"cascade": True}, "complete state|parallel"),
        ({"bypass": True}, "bypasses"),
    ],
)
def test_invalid_spn_graphs_fail_explicitly(options, match):
    with pytest.raises(ValueError, match=match):
        SpnStructure(_fixture(**options))


def test_unsupported_arx_graph_and_snapshot_isolation():
    with pytest.raises(ValueError, match="unsupported SPN"):
        SpnStructure(Speck(number_of_rounds=2))
    primitive = _fixture()
    structure = SpnStructure(primitive)
    primitive._builder.add_round()
    primitive._builder.set_output(primitive.graph.input("plaintext"))
    assert structure.linear_layers == (
        tuple(tuple(int(i == j) for i in range(4)) for j in range(4)),
    )
    assert Present(number_of_rounds=2).analysis.spn_structure().state_size == 64


@pytest.mark.parametrize("repeat_first,repeat_between", [(True, False), (False, True)])
def test_repeated_source_bits_and_singular_maps_are_retained(repeat_first, repeat_between):
    primitive = Primitive("repeated_bits", {"plaintext": UnitArrayType(Bit(), (4,))})
    primitive._builder.add_round()
    state = primitive.graph.input("plaintext")
    table = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
    first = primitive._builder.add_component(
        BitVectorSBox(state[(0, 0, 2, 3)] if repeat_first else state, table)
    )
    selected = first[(0, 0, 2, 3)] if repeat_between else first
    middle = primitive._builder.add_component(Identity(selected))
    primitive._builder.add_round()
    last = primitive._builder.add_component(BitVectorSBox(middle, table))
    primitive._builder.set_output(last)
    structure = SpnStructure(primitive)
    expected = tuple(tuple(int(i == j) for i in range(4)) for j in range(4))
    if repeat_between:
        expected = (expected[0], expected[0], expected[2], expected[3])
    assert structure.linear_layers[0] == expected
