"""Semantic checks for graph-level structural domain conversions."""

import pytest

from claasp import (
    BinaryExtensionField,
    Bit,
    Primitive,
    ScalarEvaluator,
    TransposedBatchEvaluator,
    ValueType,
    Word,
)
from claasp.components import Permutation


def _conversion_primitive() -> Primitive:
    primitive = Primitive("conversion", {"bits": ValueType(Bit(), (16,))})
    primitive._builder.add_round()
    packed = primitive._builder.pack_bits(primitive.graph.input("bits"), 8)
    swapped = primitive._builder.add_component(Permutation(packed, (1, 0)))
    unpacked = primitive._builder.unpack_bits(swapped)
    primitive._builder.set_output(unpacked)
    return primitive


def test_pack_permute_unpack_has_independent_msb_first_result():
    primitive = _conversion_primitive()
    bits = tuple((0x1234 >> position) & 1 for position in range(15, -1, -1))
    expected = tuple((0x3412 >> position) & 1 for position in range(15, -1, -1))

    result = ScalarEvaluator().evaluate(primitive, {"bits": bits})

    assert primitive.graph.resolve_selection(
        primitive.graph.bindings[0].output.select_all(), result.values
    ) == (0x12, 0x34)
    assert result.value_of("permutation_0_0") == (0x34, 0x12)
    assert result.output == expected


def test_conversion_scalar_and_transposed_batch_agree():
    primitive = _conversion_primitive()
    items = tuple(
        tuple((value >> position) & 1 for position in range(15, -1, -1))
        for value in (0x0000, 0x1234, 0xFFFF)
    )
    batch = TransposedBatchEvaluator().evaluate(primitive, {"bits": items})
    scalar = tuple(ScalarEvaluator().evaluate(primitive, {"bits": item}).output for item in items)
    assert batch.outputs == scalar


def test_conversion_components_reject_implicit_or_partial_reinterpretation():
    bit_primitive = Primitive("bits", {"state": ValueType(Bit(), (7,))})
    with pytest.raises(ValueError, match="multiple"):
        bit_primitive._builder.pack_bits(bit_primitive.graph.input("state"), 4)
    with pytest.raises(ValueError, match="Word"):
        bit_primitive._builder.unpack_bits(bit_primitive.graph.input("state"))

    word_primitive = Primitive("words", {"state": ValueType(Word(8), (2,))})
    with pytest.raises(ValueError, match="Bit"):
        word_primitive._builder.pack_bits(word_primitive.graph.input("state"), 8)


def test_pack_and_unpack_can_explicitly_cross_a_binary_field_boundary():
    primitive = Primitive("field_conversion", {"bits": ValueType(Bit(), (16,))})
    primitive._builder.add_round()
    field = BinaryExtensionField(8, 0x11D)
    packed = primitive._builder.pack_bits(primitive.graph.input("bits"), 8, output_domain=field)
    primitive._builder.set_output(primitive._builder.unpack_bits(packed))

    assert primitive.evaluate(0x12A5) == 0x12A5
    assert packed.value_type == ValueType(field, (2,))


def test_reverse_and_word_permutation_are_domain_neutral_permutations():
    primitive = Primitive("structural", {"words": ValueType(Word(5), (4,))})
    primitive._builder.add_round()
    reverse = primitive._builder.add_component(
        Permutation(primitive.graph.input("words"), (3, 2, 1, 0))
    )
    reordered = primitive._builder.add_component(Permutation(reverse, (1, 3, 0, 2)))
    primitive._builder.set_output(reordered)
    assert ScalarEvaluator().evaluate(primitive, {"words": (1, 2, 3, 4)}).output == (3, 1, 4, 2)
