import pytest

from claasp_next import Bit, Primitive, ScalarEvaluator, ValueType, bits_from_int, int_from_bits
from claasp_next.components import BitVectorSBox
from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX


def test_bit_vector_sbox_maps_one_msb_first_nibble():
    primitive = Primitive("nibble", {"value": ValueType(Bit(), (4,))})
    primitive.add_round()
    output = primitive.add_component(
        BitVectorSBox(primitive.input("value"), PRESENT_SBOX, component_id="sbox")
    )
    primitive.set_output(output)

    result = ScalarEvaluator().evaluate(primitive, {"value": bits_from_int(0xA, 4)})
    assert int_from_bits(result.output) == 0xF


def test_bit_vector_sbox_validates_output_width():
    primitive = Primitive("nibble", {"value": ValueType(Bit(), (2,))})
    with pytest.raises(ValueError, match="fit in 2 bits"):
        BitVectorSBox(primitive.input("value"), (0, 1, 2, 4), component_id="sbox")
