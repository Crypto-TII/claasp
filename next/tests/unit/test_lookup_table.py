import pytest

from claasp_next.components import BitVectorSBox, LookupTable, SBox
from claasp_next.domains import Bit, Word
from claasp_next.graph import Port, ValueType


def test_lookup_table_owns_width_validation_and_bijectivity():
    permutation = LookupTable([3, 2, 1, 0], input_bit_size=2)
    compression = LookupTable([0, 0, 1, 1], input_bit_size=2, output_bit_size=1)

    assert permutation.values == (3, 2, 1, 0)
    assert permutation.is_bijective()
    assert not compression.is_bijective()


def test_identity_lookup_can_embed_into_a_wider_output():
    identity = LookupTable.identity(input_bit_size=2, output_bit_size=3)

    assert identity.values == (0, 1, 2, 3)
    assert identity.output_bit_size == 3
    assert not identity.is_bijective()


@pytest.mark.parametrize(
    "values,input_bit_size,output_bit_size,message",
    (
        ([0, 1], 0, None, "input_bit_size must be positive"),
        ([0, 1], 1, 0, "output_bit_size must be positive"),
        ([0, 1, 2], 2, None, "lookup table must contain 4 entries"),
        ([0, 1, 2, 4], 2, None, "lookup-table outputs must fit in 2 bits"),
    ),
)
def test_lookup_table_rejects_invalid_widths_shapes_and_values(
    values, input_bit_size, output_bit_size, message
):
    with pytest.raises(ValueError, match=message):
        LookupTable(values, input_bit_size, output_bit_size)


def test_substitution_components_accept_validated_lookup_tables():
    bit_lookup = LookupTable([3, 2, 1, 0], 2)
    bit_component = BitVectorSBox(Port("bits", ValueType(Bit(), (2,))), bit_lookup)
    word_component = SBox(Port("words", ValueType(Word(2), (2,))), bit_lookup)

    assert bit_component.table == bit_lookup.values
    assert word_component.table == bit_lookup.values


def test_component_rejects_a_lookup_table_with_the_wrong_width():
    lookup = LookupTable.identity(3)

    with pytest.raises(ValueError, match="input width must match"):
        BitVectorSBox(Port("bits", ValueType(Bit(), (2,))), lookup)
    with pytest.raises(ValueError, match="widths must match"):
        SBox(Port("words", ValueType(Word(2), (1,))), lookup)
