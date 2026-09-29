import json

import pytest

from claasp import (
    Bit,
    Primitive,
    SerializationError,
    SerializationFailure,
    ValueType,
    deserialize_primitive,
    primitive_digest,
    serialize_primitive,
)
from claasp.components import Identity
from claasp.primitives import AES, Present, Speck
from claasp.primitives.block_ciphers.katan import Katan


def _toy():
    primitive = Primitive(
        "canonical", {"state": ValueType(Bit(), (4,))}, provenance=(("source", "test"),)
    )
    primitive.add_round()
    copied = primitive.add_component(Identity(primitive.input("state")[3, 1, 2, 0]))
    primitive.set_output(copied)
    return primitive


def test_canonical_bytes_are_stable_and_standard_json():
    first = serialize_primitive(_toy())
    second = serialize_primitive(_toy())
    assert first == second
    assert first.endswith(b"\n")
    assert primitive_digest(_toy()) == primitive_digest(_toy())
    parsed = json.loads(first)
    assert parsed["schema"] == "org.claasp.primitive"
    assert parsed["version"] == 1
    assert parsed["payload"]["rounds"][0]["components"][0]["inputs"][0] == {
        "positions": [3, 1, 2, 0],
        "source": "state",
    }


@pytest.mark.parametrize(
    ("primitive", "inputs"),
    [
        (AES(number_of_rounds=1), (0, 0)),
        (Present(number_of_rounds=1), (0, 0)),
        (Speck(number_of_rounds=2), (0x6574694C, 0x1918111009080100)),
        (Katan(block_bit_size=32, number_of_rounds=1), (0, 0)),
    ],
)
def test_round_trip_preserves_evaluation_metadata_topology_and_bindings(primitive, inputs):
    restored = deserialize_primitive(serialize_primitive(primitive))
    assert restored.evaluate(*inputs) == primitive.evaluate(*inputs)
    assert restored.family_name == primitive.family_name
    assert restored.kind == primitive.kind
    assert restored.input_descriptors == primitive.input_descriptors
    assert restored.provenance == primitive.provenance
    assert restored.realization == primitive.realization
    assert tuple(type(item) for item in restored.components) == tuple(
        type(item) for item in primitive.components
    )
    assert restored.bindings == primitive.bindings
    assert tuple(group.number for group in restored.rounds) == tuple(
        group.number for group in primitive.rounds
    )


def test_serialized_reference_primitives_retain_fixed_known_answers():
    aes = deserialize_primitive(serialize_primitive(AES()))
    assert (
        aes.evaluate(
            0x00112233445566778899AABBCCDDEEFF,
            0x000102030405060708090A0B0C0D0E0F,
        )
        == 0x69C4E0D86A7B0430D8CDB78070B4C55A
    )
    present = deserialize_primitive(serialize_primitive(Present()))
    assert present.evaluate(0, 0) == 0x5579C1387B228445
    speck = deserialize_primitive(serialize_primitive(Speck(64, 128)))
    assert (
        speck.evaluate(0x3B7265747475432D, 0x1B1A1918131211100B0A090803020100) == 0x8C6FA548454E028B
    )


def test_composite_scope_round_trip_preserves_hierarchy_and_named_output():
    from claasp.composites import ChaChaQuarterRound

    definition = ChaChaQuarterRound(word_size=32)
    primitive = Primitive(
        "composite", {name: value_type for name, value_type in definition.input_types}
    )
    primitive.add_round()
    instance = primitive.add_composite(definition, primitive.input_ports, scope_id="quarter")
    primitive.set_output(instance.output)
    restored = deserialize_primitive(serialize_primitive(primitive))
    assert restored.scope("quarter").definition.name == definition.name
    assert restored.scope("quarter").component_ids == instance.component_ids
    assert restored.evaluate(1, 2, 3, 4) == primitive.evaluate(1, 2, 3, 4)


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (lambda value: value.update(version=99), SerializationFailure.UNKNOWN_VERSION),
        (lambda value: value.update(schema="unknown"), SerializationFailure.UNKNOWN_SCHEMA),
        (
            lambda value: value["payload"]["rounds"][0]["components"][0].update(kind="Unknown"),
            SerializationFailure.UNKNOWN_COMPONENT,
        ),
        (
            lambda value: value["payload"]["rounds"][0]["components"][0]["inputs"][0].update(
                source="missing"
            ),
            SerializationFailure.INVALID_REFERENCE,
        ),
        (
            lambda value: value["payload"]["rounds"][0]["components"][0]["output_type"].update(
                shape=[3]
            ),
            SerializationFailure.TYPE_MISMATCH,
        ),
    ],
)
def test_strict_rejection_has_typed_reason(edit, reason):
    value = json.loads(serialize_primitive(_toy()))
    edit(value)
    with pytest.raises(SerializationError) as caught:
        deserialize_primitive(json.dumps(value))
    assert caught.value.reason is reason


def test_duplicate_fields_noncanonical_numbers_and_malformed_provenance_are_rejected():
    with pytest.raises(SerializationError, match="duplicate_field"):
        deserialize_primitive('{"schema":"x","schema":"y"}')
    value = json.loads(serialize_primitive(_toy()))
    value["payload"]["rounds"][0]["number"] = True
    with pytest.raises(SerializationError, match="canonical integer"):
        deserialize_primitive(json.dumps(value))
    value = json.loads(serialize_primitive(_toy()))
    value["payload"]["provenance"] = [["only-one"]]
    with pytest.raises(SerializationError, match="string pair"):
        deserialize_primitive(json.dumps(value))


def test_duplicate_sources_invalid_output_and_inconsistent_binding_width_are_rejected():
    value = json.loads(serialize_primitive(_toy()))
    value["payload"]["rounds"][0]["components"][0]["id"] = "state"
    with pytest.raises(SerializationError, match="duplicate_identity"):
        deserialize_primitive(json.dumps(value))
    value = json.loads(serialize_primitive(_toy()))
    value["payload"]["output"]["source"] = "missing"
    with pytest.raises(SerializationError, match="invalid_reference"):
        deserialize_primitive(json.dumps(value))

    primitive = Primitive("binding", {"state": ValueType(Bit(), (8,))})
    primitive.add_round()
    packed = primitive.pack_bits(primitive.input("state"), 4)
    primitive.set_output(packed)
    value = json.loads(serialize_primitive(primitive))
    value["payload"]["bindings"][0]["word_width"] = 3
    with pytest.raises(SerializationError, match="inconsistent_width"):
        deserialize_primitive(json.dumps(value))


def test_importing_serialization_does_not_import_optional_packages():
    import subprocess
    import sys

    code = (
        "import sys; before=set(sys.modules); import claasp.serialization; "
        "print(','.join(sorted((set(sys.modules)-before) & "
        "{'numpy','pandas','matplotlib','sklearn','sage'})))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], check=True, capture_output=True, text=True
    )
    assert completed.stdout == "\n"
