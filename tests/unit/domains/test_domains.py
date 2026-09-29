import pytest

from claasp import BinaryExtensionField, Bit, PrimeField, ValueType


def test_bit_domain_uses_canonical_integer_values():
    domain = Bit()

    assert domain.contains(0)
    assert domain.contains(1)
    assert not domain.contains(2)
    assert not domain.contains(True)
    assert domain.encoded_bit_size == 1


def test_prime_field_distinguishes_logical_and_encoded_sizes():
    domain = PrimeField(17)
    state_type = ValueType(domain, (3,))

    assert domain.contains(16)
    assert not domain.contains(17)
    assert state_type.unit_count == 3
    assert state_type.encoded_bit_size == 15


def test_binary_extension_field_records_defining_polynomial():
    aes_field = BinaryExtensionField(degree=8, modulus=0x11B)

    assert aes_field.contains(0xFF)
    assert not aes_field.contains(0x100)
    assert aes_field.encoded_bit_size == 8


@pytest.mark.parametrize("shape", [(), (0,), (-1,), (2, 0)])
def test_value_type_rejects_invalid_shapes(shape):
    with pytest.raises(ValueError):
        ValueType(Bit(), shape)


def test_domains_are_immutable_and_hashable():
    assert {PrimeField(17), PrimeField(17), PrimeField(19)} == {
        PrimeField(17),
        PrimeField(19),
    }


def test_prime_field_rejects_composite_modulus():
    with pytest.raises(ValueError, match="must be prime"):
        PrimeField(15)


def test_binary_extension_field_rejects_reducible_polynomial():
    with pytest.raises(ValueError, match="irreducible"):
        BinaryExtensionField(4, 0b10101)
