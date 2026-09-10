import pytest

from claasp_next import Cipher, PrimeField, ScalarEvaluator, ValueType
from claasp_next.ciphers.block_ciphers.aes import AES_SBOX
from claasp_next.components import SBox
from claasp_next.domains import BinaryExtensionField


def test_sbox_maps_each_field_unit_independently():
    value_type = ValueType(BinaryExtensionField(8, 0x11B), (2,))
    cipher = Cipher("sbox", {"state": value_type})
    cipher.add_round()
    output = cipher.add_component(SBox("substitute", cipher.input("state").select_all(), AES_SBOX))
    cipher.set_output(output.select_all())

    assert ScalarEvaluator().evaluate(cipher, {"state": (0x00, 0x53)}).output == (0x63, 0xED)


def test_sbox_rejects_non_dense_prime_field_domain():
    value_type = ValueType(PrimeField(17), (1,))
    cipher = Cipher("invalid_sbox", {"state": value_type})

    with pytest.raises(ValueError, match="densely encoded"):
        SBox("substitute", cipher.input("state").select_all(), range(32))


def test_sbox_validates_table_size():
    value_type = ValueType(BinaryExtensionField(8, 0x11B), (1,))
    cipher = Cipher("invalid_sbox", {"state": value_type})

    with pytest.raises(ValueError, match="256 entries"):
        SBox("substitute", cipher.input("state").select_all(), (0, 1))
