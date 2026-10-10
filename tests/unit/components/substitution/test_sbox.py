import pytest

from claasp import ArrayType, Primitive, ScalarEvaluator
from claasp.components import SBox
from claasp.domains import BinaryExtensionField, PrimeField
from claasp.primitives.block_ciphers.aes import AES_SBOX


def test_sbox_maps_each_field_unit_independently():
    array_type = ArrayType(BinaryExtensionField(8, 0x11B), (2,))
    primitive = Primitive("sbox", {"state": array_type})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        SBox(primitive.graph.input("state"), AES_SBOX, component_id="substitute")
    )
    primitive._builder.set_output(output)

    assert ScalarEvaluator().evaluate(primitive, {"state": (0x00, 0x53)}).output == (0x63, 0xED)


def test_sbox_rejects_non_dense_prime_field_domain():
    array_type = ArrayType(PrimeField(17), (1,))
    primitive = Primitive("invalid_sbox", {"state": array_type})

    with pytest.raises(ValueError, match="densely encoded"):
        SBox(primitive.graph.input("state"), range(32), component_id="substitute")


def test_sbox_validates_table_size():
    array_type = ArrayType(BinaryExtensionField(8, 0x11B), (1,))
    primitive = Primitive("invalid_sbox", {"state": array_type})

    with pytest.raises(ValueError, match="256 entries"):
        SBox(primitive.graph.input("state"), (0, 1), component_id="substitute")
