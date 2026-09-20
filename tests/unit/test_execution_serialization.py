import json

import pytest

from claasp import (
    SerializationError,
    SerializationFailure,
    deserialize_evaluation_result,
    deserialize_execution_trace,
    serialize_artifact,
    serialize_evaluation_result,
    serialize_execution_trace,
)
from claasp.annotations import GraphAnnotation
from claasp.primitives import Present, Speck
from claasp.semantics import CONCRETE


def test_execution_trace_is_canonical_and_bound_to_the_exact_graph():
    primitive = Speck(32, 64, number_of_rounds=2)
    result = primitive.evaluate_with_trace(0x6574694C, 0x1918111009080100)
    data = serialize_execution_trace(result.trace)
    assert data == serialize_execution_trace(result.trace)
    restored = deserialize_execution_trace(data, primitive)
    assert restored.annotation.entries == result.trace.annotation.entries
    with pytest.raises(SerializationError, match="different primitive graph"):
        deserialize_execution_trace(data, Speck(32, 64, number_of_rounds=1))


def test_evaluation_result_round_trip_preserves_values_output_and_provenance():
    primitive = Present(number_of_rounds=2)
    result = primitive.evaluate_with_trace(0, 0)
    data = serialize_evaluation_result(result)
    restored = deserialize_evaluation_result(data, primitive)
    assert restored.values == result.values
    assert restored.output == result.output
    assert restored.provenance == result.provenance
    assert serialize_artifact(result) == data


def test_result_rejects_modified_values_output_order_and_provenance():
    primitive = Speck(32, 64, number_of_rounds=1)
    value = json.loads(serialize_evaluation_result(primitive.evaluate_with_trace(0, 0)))
    value["payload"]["output"][0] ^= 1
    with pytest.raises(SerializationError) as caught:
        deserialize_evaluation_result(json.dumps(value), primitive)
    assert caught.value.reason is SerializationFailure.TYPE_MISMATCH

    value = json.loads(serialize_evaluation_result(primitive.evaluate_with_trace(0, 0)))
    value["payload"]["values"].reverse()
    with pytest.raises(SerializationError, match="semantic order"):
        deserialize_evaluation_result(json.dumps(value), primitive)
    value = json.loads(serialize_evaluation_result(primitive.evaluate_with_trace(0, 0)))
    value["payload"]["provenance"]["driver"]["kind"] = "renderer"
    with pytest.raises(SerializationError, match="execution-engine"):
        deserialize_evaluation_result(json.dumps(value), primitive)


def test_unregistered_annotations_and_analysis_results_are_typed_rejections():
    primitive = Present(number_of_rounds=1)
    annotation = GraphAnnotation(primitive, CONCRETE, ())
    with pytest.raises(SerializationError) as caught:
        serialize_artifact(annotation)
    assert caught.value.reason is SerializationFailure.UNSUPPORTED_ARTIFACT


def test_trace_rejects_unknown_sources_duplicate_entries_and_noncanonical_values():
    primitive = Present(number_of_rounds=1)
    result = primitive.evaluate_with_trace(0, 0)
    value = json.loads(serialize_execution_trace(result.trace))
    value["payload"]["entries"][0]["source"] = "missing"
    with pytest.raises(SerializationError, match="invalid_reference"):
        deserialize_execution_trace(json.dumps(value), primitive)
    value = json.loads(serialize_execution_trace(result.trace))
    value["payload"]["entries"].append(value["payload"]["entries"][0])
    with pytest.raises(SerializationError, match="duplicate_identity"):
        deserialize_execution_trace(json.dumps(value), primitive)
    value = json.loads(serialize_execution_trace(result.trace))
    value["payload"]["entries"][0]["value"][0] = True
    with pytest.raises(SerializationError, match="canonical integer"):
        deserialize_execution_trace(json.dumps(value), primitive)
