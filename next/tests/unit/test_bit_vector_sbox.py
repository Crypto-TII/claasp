import pytest

from claasp_next import Bit, Cipher, ScalarEvaluator, ValueType, bits_from_int, int_from_bits
from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX
from claasp_next.components import BitVectorSBox


def test_bit_vector_sbox_maps_one_msb_first_nibble():
    cipher = Cipher("nibble", {"value": ValueType(Bit(), (4,))})
    cipher.add_round()
    output = cipher.add_component(BitVectorSBox(
        cipher.input("value"), PRESENT_SBOX, component_id="sbox"
    ))
    cipher.set_output(output)

    result = ScalarEvaluator().evaluate(cipher, {"value": bits_from_int(0xA, 4)})
    assert int_from_bits(result.output) == 0xF


def test_bit_vector_sbox_validates_output_width():
    cipher = Cipher("nibble", {"value": ValueType(Bit(), (2,))})
    with pytest.raises(ValueError, match="fit in 2 bits"):
        BitVectorSBox(cipher.input("value"), (0, 1, 2, 4), component_id="sbox")
