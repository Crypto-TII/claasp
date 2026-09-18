"""Semantic checks for reviewed primitive-level inversion equivalents."""

import pytest

from claasp_next.primitives import (
    AradiSBox, Ascon, AsconSboxSigmaNoMatrix, Gaston, GastonSbox,
)


@pytest.mark.parametrize(
    "primitive, values",
    (
        (AradiSBox(number_of_rounds=1), (0x0123456789ABCDEFFEDCBA9876543210,
                                         0x0123456789ABCDEFFEDCBA9876543210FEDCBA98765432100123456789ABCDEF)),
        (Ascon(number_of_rounds=1), (0x0123456789ABCDEF,)),
        (AsconSboxSigmaNoMatrix(number_of_rounds=1), (0x0123456789ABCDEF,)),
        (Gaston(number_of_rounds=1), (0x0123456789ABCDEF,)),
        (GastonSbox(number_of_rounds=1), (0x0123456789ABCDEF,)),
    ),
)
def test_reviewed_equivalent_realizations_recover_source_inputs(primitive, values):
    values = tuple(
        value & ((1 << port.value_type.encoded_bit_size) - 1)
        for value, port in zip(values, primitive.inputs())
    )
    inverse = primitive.inverse().primitive

    assert inverse.evaluate(primitive.evaluate(*values), *values[1:]) == values[0]
    assert inverse.realization == primitive.realization
    assert [record.operation for record in inverse.transformation_provenance] == [
        "inverse_equivalent", "inverse",
    ]
