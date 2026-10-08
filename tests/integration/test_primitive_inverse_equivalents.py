"""Semantic checks for reviewed primitive-level inversion equivalents."""

import pytest

from claasp.primitives import (
    Aradi,
    AradiSBox,
    Ascon,
    AsconSboxSigmaNoMatrix,
    Chilow,
    Gaston,
    GastonSbox,
    Gimli,
    GimliSbox,
    Keccak,
    KeccakInvertible,
    KeccakSbox,
    Norx,
    QARMAv2,
    Subterranean,
    TinyJambuFSRWordBased,
    Xoodoo,
    XoodooInvertible,
    XoodooSbox,
)


@pytest.mark.parametrize(
    "primitive_factory, values",
    (
        pytest.param(
            lambda: Aradi(number_of_rounds=1), (0x0123456789ABCDEF, 0xFEDCBA9876543210), id="aradi"
        ),
        pytest.param(
            lambda: AradiSBox(number_of_rounds=1),
            (0x0123456789ABCDEF, 0xFEDCBA9876543210),
            id="aradi-sbox",
        ),
        pytest.param(lambda: Ascon(number_of_rounds=1), (0x0123456789ABCDEF,), id="ascon"),
        pytest.param(
            lambda: AsconSboxSigmaNoMatrix(number_of_rounds=1),
            (0x0123456789ABCDEF,),
            id="ascon-no-matrix",
        ),
        pytest.param(lambda: Gaston(number_of_rounds=1), (0x0123456789ABCDEF,), id="gaston"),
        pytest.param(
            lambda: GastonSbox(number_of_rounds=1), (0x0123456789ABCDEF,), id="gaston-sbox"
        ),
        pytest.param(
            lambda: Gimli(number_of_rounds=1, word_size=8), (0x0123456789ABCDEF,), id="gimli"
        ),
        pytest.param(
            lambda: GimliSbox(number_of_rounds=1, word_size=8),
            (0x0123456789ABCDEF,),
            id="gimli-sbox",
        ),
        pytest.param(
            lambda: Keccak(number_of_rounds=1, word_size=8), (0x0123456789ABCDEF,), id="keccak"
        ),
        pytest.param(
            lambda: KeccakInvertible(number_of_rounds=1, word_size=8),
            (0x0123456789ABCDEF,),
            id="keccak-invertible",
        ),
        pytest.param(
            lambda: KeccakSbox(number_of_rounds=1, word_size=8),
            (0x0123456789ABCDEF,),
            id="keccak-sbox",
        ),
        pytest.param(
            lambda: Norx(number_of_rounds=1, word_size=32), (0x0123456789ABCDEF,), id="norx"
        ),
        pytest.param(
            lambda: QARMAv2(number_of_rounds=1),
            (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xA5A5),
            id="qarmav2",
        ),
        pytest.param(
            lambda: TinyJambuFSRWordBased(number_of_rounds=32),
            (0x0123456789ABCDEF, 0xFEDCBA9876543210),
            id="tinyjambu-fsr",
        ),
        pytest.param(lambda: Xoodoo(number_of_rounds=1), (0x0123456789ABCDEF,), id="xoodoo"),
        pytest.param(
            lambda: XoodooInvertible(number_of_rounds=1),
            (0x0123456789ABCDEF,),
            id="xoodoo-invertible",
        ),
        pytest.param(
            lambda: XoodooSbox(number_of_rounds=1), (0x0123456789ABCDEF,), id="xoodoo-sbox"
        ),
    ),
)
def test_reviewed_equivalent_realizations_recover_source_inputs(primitive_factory, values):
    primitive = primitive_factory()
    inputs = {
        name: value & ((1 << port.value_type.encoded_bit_size) - 1)
        for value, (name, port) in zip(values, primitive.graph.input_ports.items())
    }
    recover = next(
        (name for name in inputs if primitive.graph.input_descriptor(name).role == "plaintext"),
        next(iter(inputs)),
    )
    inverse = primitive.edit.inverse(recover).primitive
    inverse_inputs = {"output": primitive.evaluate(inputs)}
    inverse_inputs.update((name, value) for name, value in inputs.items() if name != recover)

    assert inverse.evaluate(inverse_inputs) == inputs[recover]
    assert inverse.realization == primitive.realization
    assert [record.operation for record in inverse.transformation_provenance] == [
        "inverse_equivalent",
        "inverse",
    ]


@pytest.mark.parametrize(
    "primitive_factory, values",
    (
        pytest.param(
            lambda: Subterranean(), (0x123456789ABCDEF, 0xFEDCBA9876543210), id="subterranean"
        ),
        pytest.param(
            lambda: Chilow(), (0x123456789A, 0x1122334455667788, 0xFEDCBA9876543210), id="chilow"
        ),
    ),
)
def test_reviewed_direct_inverses_recover_inputs(primitive_factory, values):
    primitive = primitive_factory()
    inputs = {
        name: value & ((1 << port.value_type.encoded_bit_size) - 1)
        for value, (name, port) in zip(values, primitive.graph.input_ports.items())
    }
    inverse = primitive.edit.inverse("plaintext").primitive
    inverse_inputs = {"output": primitive.evaluate(inputs)}
    inverse_inputs.update((name, value) for name, value in inputs.items() if name != "plaintext")

    assert inverse.evaluate(inverse_inputs) == inputs["plaintext"]
    assert [record.operation for record in inverse.transformation_provenance] == [
        "inverse_equivalent",
        "inverse",
    ]
