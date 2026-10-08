import pytest

from claasp import Bit, Primitive, ScalarEvaluator, ValueType, bits_from_int, int_from_bits
from claasp.components import BitVectorSBox
from claasp.primitives.block_ciphers.present import PRESENT_SBOX


def test_bit_vector_sbox_maps_one_msb_first_nibble():
    primitive = Primitive("nibble", {"value": ValueType(Bit(), (4,))})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        BitVectorSBox(primitive.graph.input("value"), PRESENT_SBOX, component_id="sbox")
    )
    primitive._builder.set_output(output)

    result = ScalarEvaluator().evaluate(primitive, {"value": bits_from_int(0xA, 4)})
    assert int_from_bits(result.output) == 0xF


def test_bit_vector_sbox_validates_output_width():
    primitive = Primitive("nibble", {"value": ValueType(Bit(), (2,))})
    with pytest.raises(ValueError, match="fit in 2 bits"):
        BitVectorSBox(primitive.graph.input("value"), (0, 1, 2, 4), component_id="sbox")
