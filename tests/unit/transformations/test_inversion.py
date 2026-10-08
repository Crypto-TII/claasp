import random

import pytest

from claasp import (
    Bit,
    Primitive,
    PrimitiveKind,
    TransformationError,
    TransformationFailureReason,
    ValueType,
    Word,
    invert_primitive,
    partial_inverse,
)
from claasp.catalogue import catalogue
from claasp.components import Identity, Permutation, Shift, Xor
from claasp.primitives import Present, Simon, Speck
from claasp.primitives._catalogue_exports import load_export

PLAINTEXT = 0x6574694C
KEY = 0x1918111009080100

REVIEWED_RETAINED_INPUT_PRIMITIVES = (
    "Add",
    "BinaryAffineMap",
    "BitVectorSBox",
    "BitwiseNot",
    "ChaChaKeystreamBlock",
    "CipherFour",
    "FeedbackRegister",
    "Heys",
    "IDEAMultiply",
    "Identity",
    "LinearMap",
    "ModularAdd",
    "ModularSubtract",
    "Permutation",
    "Power",
    "Rotate",
    "SBox",
    "ToyAES",
    "ToyFeistel",
    "ToySPN1",
    "ToySPN2",
    "VariableRotate",
    "Xor",
)


def test_complete_speck_inverse_matches_fixed_and_seeded_independent_evaluation():
    primitive = Speck()
    inverse = invert_primitive(primitive).primitive

    assert primitive.evaluate(PLAINTEXT, KEY) == 0xA86842F2
    assert inverse.evaluate(0xA86842F2, KEY) == PLAINTEXT
    random_source = random.Random(0xC1AA5)
    for _ in range(20):
        plaintext = random_source.getrandbits(32)
        key = random_source.getrandbits(64)
        assert inverse.evaluate(primitive.evaluate(plaintext, key), key) == plaintext


@pytest.mark.parametrize("primitive_name", REVIEWED_RETAINED_INPUT_PRIMITIVES)
def test_reviewed_retained_input_obligations_round_trip(primitive_name):
    record = catalogue.primitive(primitive_name)
    parameters = dict(record.parameter_sets[0].values)
    primitive = load_export(primitive_name)(**parameters)
    by_role = {primitive.input_descriptor(name).role: name for name in primitive.input_ports}
    recover_input = next(
        (
            by_role[role]
            for role in ("plaintext", "state", "input_state", "input")
            if role in by_role
        ),
        next(iter(primitive.input_ports)),
    )
    inverse = primitive.inverse(recover_input).primitive

    assert record.bijectivity_obligation
    for sample in (0x13579BDF, 0xECA86420):
        values = {
            name: (sample * (index + 1)) & ((1 << port.value_type.encoded_bit_size) - 1)
            for index, (name, port) in enumerate(primitive.input_ports.items())
        }
        output = primitive.evaluate(values)
        inverse_values = {"output": output}
        inverse_values.update(
            (name, value) for name, value in values.items() if name != recover_input
        )
        assert inverse.evaluate(inverse_values) == values[recover_input]


@pytest.mark.parametrize(
    ("primitive", "plaintext", "key", "ciphertext"),
    (
        (Present(number_of_rounds=2), 0, 0, 0xD0FF18FFFF008001),
        (Simon(number_of_rounds=2), 0x6120676E, 0x1211100A09080201, 0x6CD2E1AE),
    ),
)
def test_representative_bit_and_feistel_primitive_inverses_match_fixed_evidence(
    primitive,
    plaintext,
    key,
    ciphertext,
):
    assert primitive.evaluate(plaintext, key) == ciphertext
    assert invert_primitive(primitive).primitive.evaluate(ciphertext, key) == plaintext


def test_inverse_preserves_realization_and_records_transformation_separately():
    primitive = Speck(number_of_rounds=2)
    result = primitive.inverse()
    inverse = result.primitive

    assert inverse.kind is PrimitiveKind.BLOCK_CIPHER
    assert inverse.realization is primitive.realization
    assert inverse.transformation_provenance[-1].operation == "inverse"
    assert primitive.transformation_provenance == ()
    assert not any(isinstance(component, Identity) for component in inverse.components)
    assert tuple(inverse.input_ports) == ("output", "key")


def test_partial_inverse_recovers_through_equivalent_fanout_wires():
    graph = Primitive(
        "fanout",
        {"left": ValueType(Word(8), (1,)), "right": ValueType(Word(8), (1,))},
    )
    graph._builder.add_round()
    first = graph._builder.add_component(Xor(graph.inputs()))
    second = graph._builder.add_component(Xor((first, graph.input("right"))))
    graph._builder.set_output(second)

    inverse = partial_inverse(
        graph,
        graph.input("left"),
        known={"observed": graph.output, "right": graph.input("right")},
    ).primitive

    assert inverse.evaluate(0xA5, 0x3C) == 0xA5
    assert len(inverse.components) == 2
    assert not any(isinstance(component, Identity) for component in inverse.components)


def test_partial_inverse_can_recover_an_internal_wire():
    graph = Primitive(
        "internal",
        {"left": ValueType(Word(8), (1,)), "right": ValueType(Word(8), (1,))},
    )
    graph._builder.add_round()
    mixed = graph._builder.add_component(Xor(graph.inputs()))
    rotated = graph._builder.add_component(Xor((mixed, graph.input("right"))))
    graph._builder.set_output(rotated)

    inverse = partial_inverse(
        graph,
        mixed,
        known={"observed": graph.output, "right": graph.input("right")},
    ).primitive
    assert inverse.evaluate(0xA5, 0x3C) == 0x99


def test_joint_xor_region_recovers_multiple_predecessors_without_a_solver():
    graph = Primitive(
        "joint",
        {"state": ValueType(Word(4), (3,))},
        kind=PrimitiveKind.PERMUTATION,
    )
    graph._builder.add_round()
    state = graph.input("state")
    x, y, z = (state[index] for index in range(3))
    outputs = (
        graph._builder.add_component(Xor((x, y))),
        graph._builder.add_component(Xor((y, z))),
        graph._builder.add_component(Xor((x, y, z))),
    )
    graph._builder.set_output(graph._builder.join(*outputs))

    inverse = invert_primitive(graph).primitive

    for value in range(1 << 12):
        assert inverse.evaluate(graph.evaluate(value)) == value


def test_pack_unpack_bindings_remain_structural_during_inversion():
    graph = Primitive("packed", {"state": ValueType(Word(8), (1,))}, kind=PrimitiveKind.PERMUTATION)
    graph._builder.add_round()
    bits = graph._builder.unpack_bits(graph.input("state"))
    permuted = graph._builder.add_component(Permutation(bits, (7, 6, 5, 4, 3, 2, 1, 0)))
    graph._builder.set_output(graph._builder.pack_bits(permuted, 8))

    inverse = invert_primitive(graph).primitive
    for value in (0, 1, 0x5A, 0x80, 0xFF):
        assert inverse.evaluate(graph.evaluate(value)) == value
    assert tuple(binding.kind.value for binding in inverse.bindings) == ("unpack_bits", "pack_bits")
    assert not any(isinstance(component, Identity) for component in inverse.components)


def test_stalls_report_multiple_predecessors_information_loss_and_disconnection():
    speck = Speck(number_of_rounds=1)
    with pytest.raises(TransformationError) as multiple:
        invert_primitive(speck, retained_inputs=())
    assert multiple.value.reason is TransformationFailureReason.MULTIPLE_PREDECESSORS

    shifted = Primitive("shifted", {"state": ValueType(Word(8), (1,))})
    shifted._builder.add_round()
    shifted._builder.set_output(shifted._builder.add_component(Shift(shifted.input("state"), 1, "left", "loss")))
    with pytest.raises(TransformationError) as loss:
        invert_primitive(shifted)
    assert loss.value.reason is TransformationFailureReason.INFORMATION_LOSS
    assert loss.value.source_ids == ("loss",)

    disconnected = Primitive(
        "disconnected",
        {"left": ValueType(Bit(), (1,)), "right": ValueType(Bit(), (1,))},
    )
    disconnected._builder.add_round()
    disconnected._builder.set_output(disconnected.input("right"))
    with pytest.raises(TransformationError) as absent:
        partial_inverse(
            disconnected,
            disconnected.input("left"),
            known={"observed": disconnected.output},
        )
    assert absent.value.reason is TransformationFailureReason.DISCONNECTED_DEPENDENCY


def test_zero_input_primitive_reports_an_ambiguous_boundary():
    graph = Primitive("constant", {})
    graph._builder.add_round()
    from claasp.components import Constant

    graph._builder.set_output(graph._builder.add_component(Constant(ValueType(Bit(), (1,)), (1,))))

    with pytest.raises(TransformationError) as caught:
        invert_primitive(graph)
    assert caught.value.reason is TransformationFailureReason.AMBIGUOUS_BOUNDARY
