"""Encoded wiring remains correct when authoring continues after inspection."""

from claasp import Primitive, UnitArrayType
from claasp.components import Xor
from claasp.unit_types import Word


def test_bit_sources_remain_correct_after_new_bindings_and_components():
    primitive = Primitive(
        "wiring", {"state": UnitArrayType(Word(2), (2,)), "key": UnitArrayType(Word(2), (1,))}
    )
    primitive._builder.add_round()
    state, key = primitive.graph.input("state"), primitive.graph.input("key")
    assert primitive.graph.selection_bit_sources(state[1]) == (("state", 2), ("state", 3))
    joined = primitive._builder.join(state[0], key)
    unpacked = primitive._builder.unpack_bits(joined)
    assert primitive.graph.selection_bit_sources(unpacked[:]) == (
        ("state", 0),
        ("state", 1),
        ("key", 0),
        ("key", 1),
    )
    output = primitive._builder.add_component(Xor((state[0], key)))
    assert primitive.graph.selection_bit_sources(output[:]) == (
        (output.source_id, 0),
        (output.source_id, 1),
    )
    assert primitive.graph.selection_bit_sources(state[1]) == (("state", 2), ("state", 3))
