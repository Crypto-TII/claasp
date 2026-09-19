"""Versioned serialization for concrete execution artifacts."""

from __future__ import annotations

import json

from claasp_next.annotations import AnnotationEntry, AnnotationRole, ExecutionTrace, GraphAnnotation
from claasp_next.graph import Primitive
from claasp_next.provenance import DriverIdentity, DriverKind, ResultProvenance, TransformationRecord
from claasp_next.representations.execution import EvaluationResult
from claasp_next.semantics import CONCRETE
from claasp_next.serialization.errors import SerializationError, SerializationFailure
from claasp_next.serialization.primitive import (
    _array, _decode_realization, _encode_realization, _integer, _object, _pairs,
    _string, _unique_object, primitive_digest,
)


EXECUTION_TRACE_SCHEMA_ID = "org.claasp.execution-trace"
EVALUATION_RESULT_SCHEMA_ID = "org.claasp.evaluation-result"
EXECUTION_SCHEMA_VERSION = 1


def _canonical(envelope) -> bytes:
    return (json.dumps(
        envelope, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True,
    ) + "\n").encode("utf-8")


def _values(value, path):
    values = []
    for index, item in enumerate(_array(value, path=path)):
        values.append(_integer(item, path=f"{path}[{index}]", minimum=0))
    return tuple(values)


def _validate_value(primitive, source_id, value, path):
    try:
        value_type = primitive.port(source_id).value_type
    except KeyError as error:
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE, f"unknown graph source {source_id!r}", path=path,
        ) from error
    if len(value) != value_type.unit_count:
        raise SerializationError(
            SerializationFailure.INCONSISTENT_WIDTH,
            f"source {source_id!r} requires {value_type.unit_count} units", path=path,
        )
    for scalar in value:
        if not value_type.domain.contains(scalar):
            raise SerializationError(
                SerializationFailure.MALFORMED_VALUE,
                f"value {scalar!r} is outside the source domain", path=path,
            )


def serialize_execution_trace(trace: ExecutionTrace) -> bytes:
    """Serialize one concrete trace without serializing its graph again."""

    if not isinstance(trace, ExecutionTrace):
        raise TypeError("serialize_execution_trace requires an ExecutionTrace")
    primitive = trace.annotation.primitive
    entries = []
    for entry in trace.annotation.entries:
        if not isinstance(entry.value, tuple) or any(
            not isinstance(item, int) or isinstance(item, bool) for item in entry.value
        ):
            raise SerializationError(
                SerializationFailure.UNSUPPORTED_ARTIFACT,
                "concrete trace values must be tuples of canonical integers",
            )
        entries.append({
            "role": entry.role.value, "source": entry.source_id, "value": list(entry.value),
        })
    return _canonical({
        "artifact": "execution_trace",
        "payload": {"entries": entries, "primitive_digest": primitive_digest(primitive)},
        "schema": EXECUTION_TRACE_SCHEMA_ID,
        "version": EXECUTION_SCHEMA_VERSION,
    })


def deserialize_execution_trace(data: bytes | str, primitive: Primitive) -> ExecutionTrace:
    """Decode a concrete trace and bind it to the exact supplied primitive."""

    envelope = _load_envelope(data, EXECUTION_TRACE_SCHEMA_ID, "execution_trace")
    payload = envelope["payload"]
    _object(payload, {"entries", "primitive_digest"}, path="$.payload")
    if payload["primitive_digest"] != primitive_digest(primitive):
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH,
            "execution artifact belongs to a different primitive graph",
            path="$.payload.primitive_digest",
        )
    entries = []
    seen = set()
    input_names = set(primitive.input_ports)
    component_ids = {item.component_id for item in primitive.components}
    for index, item in enumerate(_array(payload["entries"], path="$.payload.entries")):
        path = f"$.payload.entries[{index}]"
        _object(item, {"role", "source", "value"}, path=path)
        source = _string(item["source"], path=f"{path}.source")
        try:
            role = AnnotationRole(item["role"])
        except (TypeError, ValueError) as error:
            raise SerializationError(SerializationFailure.MALFORMED_VALUE, "unknown annotation role", path=f"{path}.role") from error
        identity = (role, source)
        if identity in seen:
            raise SerializationError(SerializationFailure.DUPLICATE_IDENTITY, "duplicate trace entry", path=path)
        seen.add(identity)
        value = _values(item["value"], f"{path}.value")
        if role is AnnotationRole.INPUT:
            if source not in input_names:
                raise SerializationError(SerializationFailure.INVALID_REFERENCE, "unknown input trace source", path=f"{path}.source")
            _validate_value(primitive, source, value, f"{path}.value")
        elif role is AnnotationRole.COMPONENT:
            if source not in component_ids:
                raise SerializationError(SerializationFailure.INVALID_REFERENCE, "unknown component trace source", path=f"{path}.source")
            _validate_value(primitive, source, value, f"{path}.value")
        else:
            if source != "primitive_output" or primitive.output is None:
                raise SerializationError(SerializationFailure.INVALID_REFERENCE, "invalid primitive output trace source", path=f"{path}.source")
            value_type = primitive.output.value_type
            if len(value) != value_type.unit_count or any(not value_type.domain.contains(unit) for unit in value):
                raise SerializationError(SerializationFailure.INCONSISTENT_WIDTH, "invalid primitive output trace value", path=f"{path}.value")
        entries.append(AnnotationEntry(source, role, value))
    try:
        return ExecutionTrace(GraphAnnotation(primitive, CONCRETE, tuple(entries)))
    except (TypeError, ValueError) as error:
        raise SerializationError(SerializationFailure.MALFORMED_VALUE, str(error), path="$.payload.entries") from error


def _encode_provenance(provenance):
    return {
        "driver": {
            "kind": provenance.driver.kind.value,
            "name": provenance.driver.name,
            "version": provenance.driver.version,
        },
        "primitive": provenance.primitive,
        "realization": _encode_realization(provenance.realization),
        "transformations": [
            {"operation": item.operation, "parameters": [list(pair) for pair in item.parameters], "source_identity": item.source_identity}
            for item in provenance.transformations
        ],
    }


def _decode_provenance(value, primitive, path):
    _object(value, {"driver", "primitive", "realization", "transformations"}, path=path)
    driver = value["driver"]
    _object(driver, {"kind", "name", "version"}, path=f"{path}.driver")
    version = driver["version"]
    if version is not None:
        version = _string(version, path=f"{path}.driver.version")
    try:
        identity = DriverIdentity(
            _string(driver["name"], path=f"{path}.driver.name"),
            DriverKind(driver["kind"]), version,
        )
        realization = _decode_realization(value["realization"], f"{path}.realization")
        transformations = []
        for index, item in enumerate(_array(value["transformations"], path=f"{path}.transformations")):
            item_path = f"{path}.transformations[{index}]"
            _object(item, {"operation", "parameters", "source_identity"}, path=item_path)
            source_identity = item["source_identity"]
            if source_identity is not None:
                source_identity = _string(source_identity, path=f"{item_path}.source_identity")
            transformations.append(TransformationRecord(
                _string(item["operation"], path=f"{item_path}.operation"),
                _pairs(item["parameters"], f"{item_path}.parameters"), source_identity,
            ))
        result = ResultProvenance(
            _string(value["primitive"], path=f"{path}.primitive"), realization,
            identity, tuple(transformations),
        )
    except (TypeError, ValueError) as error:
        raise SerializationError(SerializationFailure.MALFORMED_VALUE, str(error), path=path) from error
    if (
        result.primitive != primitive.family_name
        or result.realization != primitive.realization
        or result.transformations != primitive.transformation_provenance
    ):
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH,
            "result provenance does not match the supplied primitive realization",
            path=path,
        )
    if result.driver.kind is not DriverKind.EXECUTION_ENGINE:
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH,
            "an evaluation result requires execution-engine driver provenance",
            path=f"{path}.driver.kind",
        )
    return result


def serialize_evaluation_result(result: EvaluationResult) -> bytes:
    """Serialize a concrete scalar evaluation result and its provenance."""

    if not isinstance(result, EvaluationResult):
        raise TypeError("serialize_evaluation_result requires an EvaluationResult")
    primitive = result.trace.annotation.primitive
    expected_order = (
        tuple(primitive.input_ports)
        + tuple(item.component_id for item in primitive.components)
        + tuple(item.binding_id for item in primitive.bindings)
    )
    if set(result.values) != set(expected_order):
        raise SerializationError(
            SerializationFailure.MALFORMED_VALUE,
            "evaluation values must cover every graph source exactly",
        )
    values = []
    for source_id in expected_order:
        value = tuple(result.values[source_id])
        _validate_value(primitive, source_id, value, f"$.payload.values.{source_id}")
        values.append({"source": source_id, "value": list(value)})
    return _canonical({
        "artifact": "evaluation_result",
        "payload": {
            "output": None if result.output is None else list(result.output),
            "primitive_digest": primitive_digest(primitive),
            "provenance": _encode_provenance(result.provenance),
            "values": values,
        },
        "schema": EVALUATION_RESULT_SCHEMA_ID,
        "version": EXECUTION_SCHEMA_VERSION,
    })


def deserialize_evaluation_result(data: bytes | str, primitive: Primitive) -> EvaluationResult:
    """Decode and fully validate one scalar evaluation result."""

    envelope = _load_envelope(data, EVALUATION_RESULT_SCHEMA_ID, "evaluation_result")
    payload = envelope["payload"]
    _object(payload, {"output", "primitive_digest", "provenance", "values"}, path="$.payload")
    if payload["primitive_digest"] != primitive_digest(primitive):
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH, "evaluation result belongs to a different primitive graph",
            path="$.payload.primitive_digest",
        )
    expected_order = (
        tuple(primitive.input_ports)
        + tuple(item.component_id for item in primitive.components)
        + tuple(item.binding_id for item in primitive.bindings)
    )
    values = {}
    order = []
    for index, item in enumerate(_array(payload["values"], path="$.payload.values")):
        path = f"$.payload.values[{index}]"
        _object(item, {"source", "value"}, path=path)
        source = _string(item["source"], path=f"{path}.source")
        if source in values:
            raise SerializationError(SerializationFailure.DUPLICATE_IDENTITY, "duplicate result source", path=path)
        value = _values(item["value"], f"{path}.value")
        _validate_value(primitive, source, value, f"{path}.value")
        order.append(source)
        values[source] = value
    if tuple(order) != expected_order:
        raise SerializationError(
            SerializationFailure.INVALID_REFERENCE,
            "evaluation result sources are missing, unknown, or out of semantic order",
            path="$.payload.values",
        )
    output = None if payload["output"] is None else _values(payload["output"], "$.payload.output")
    expected_output = None if primitive.output is None else primitive.resolve_selection(primitive.output, values)
    if output != expected_output:
        raise SerializationError(
            SerializationFailure.TYPE_MISMATCH,
            "serialized output does not match graph values and output binding",
            path="$.payload.output",
        )
    provenance = _decode_provenance(payload["provenance"], primitive, "$.payload.provenance")
    annotation_values = {
        source_id: values[source_id]
        for source_id in tuple(primitive.input_ports) + tuple(item.component_id for item in primitive.components)
    }
    trace = ExecutionTrace(GraphAnnotation.from_values(
        primitive, CONCRETE, annotation_values, output=output,
    ))
    return EvaluationResult(values, output, trace, provenance)


def serialize_artifact(value) -> bytes:
    """Serialize one explicitly supported graph or execution artifact."""

    from claasp_next.serialization.primitive import serialize_primitive

    if isinstance(value, Primitive):
        return serialize_primitive(value)
    if isinstance(value, EvaluationResult):
        return serialize_evaluation_result(value)
    if isinstance(value, ExecutionTrace):
        return serialize_execution_trace(value)
    raise SerializationError(
        SerializationFailure.UNSUPPORTED_ARTIFACT,
        f"serialization is not registered for {type(value).__name__}",
    )


def _load_envelope(data, schema, artifact):
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SerializationError(SerializationFailure.INVALID_JSON, "input is not valid UTF-8") from error
    if not isinstance(data, str):
        raise TypeError("serialized artifact must be bytes or str")
    try:
        envelope = json.loads(data, object_pairs_hook=_unique_object)
    except SerializationError:
        raise
    except json.JSONDecodeError as error:
        raise SerializationError(SerializationFailure.INVALID_JSON, str(error)) from error
    _object(envelope, {"artifact", "payload", "schema", "version"}, path="$")
    if envelope["schema"] != schema:
        raise SerializationError(SerializationFailure.UNKNOWN_SCHEMA, f"unsupported schema {envelope['schema']!r}", path="$.schema")
    if envelope["version"] != EXECUTION_SCHEMA_VERSION:
        raise SerializationError(SerializationFailure.UNKNOWN_VERSION, f"unsupported version {envelope['version']!r}", path="$.version")
    if envelope["artifact"] != artifact:
        raise SerializationError(SerializationFailure.UNKNOWN_ARTIFACT, f"expected {artifact!r}", path="$.artifact")
    return envelope


__all__ = [
    "EVALUATION_RESULT_SCHEMA_ID", "EXECUTION_SCHEMA_VERSION", "EXECUTION_TRACE_SCHEMA_ID",
    "deserialize_evaluation_result", "deserialize_execution_trace", "serialize_artifact",
    "serialize_evaluation_result", "serialize_execution_trace",
]
