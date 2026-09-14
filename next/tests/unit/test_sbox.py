import pytest

from claasp_next import Primitive, PrimeField, ScalarEvaluator, ValueType
from claasp_next.primitives.block_ciphers.aes import AES_SBOX
from claasp_next.components import SBox
from claasp_next.domains import BinaryExtensionField


def test_sbox_maps_each_field_unit_independently():
    value_type = ValueType(BinaryExtensionField(8, 0x11B), (2,))
    primitive = Primitive("sbox", {"state": value_type})
    primitive.add_round()
    output = primitive.add_component(SBox(primitive.input("state"), AES_SBOX, component_id="substitute"))
    primitive.set_output(output)

    assert ScalarEvaluator().evaluate(primitive, {"state": (0x00, 0x53)}).output == (0x63, 0xED)


def test_sbox_rejects_non_dense_prime_field_domain():
    value_type = ValueType(PrimeField(17), (1,))
    primitive = Primitive("invalid_sbox", {"state": value_type})

    with pytest.raises(ValueError, match="densely encoded"):
        SBox(primitive.input("state"), range(32), component_id="substitute")


def test_sbox_validates_table_size():
    value_type = ValueType(BinaryExtensionField(8, 0x11B), (1,))
    primitive = Primitive("invalid_sbox", {"state": value_type})

    with pytest.raises(ValueError, match="256 entries"):
        SBox(primitive.input("state"), (0, 1), component_id="substitute")
