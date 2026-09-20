"""Versioned, dependency-free CLAASP serialization."""

from claasp.serialization.errors import (
    SerializationDiagnostic,
    SerializationError,
    SerializationFailure,
)
from claasp.serialization.execution import (
    EVALUATION_RESULT_SCHEMA_ID,
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_TRACE_SCHEMA_ID,
    deserialize_evaluation_result,
    deserialize_execution_trace,
    serialize_artifact,
    serialize_evaluation_result,
    serialize_execution_trace,
)
from claasp.serialization.primitive import (
    SCHEMA_ID,
    SCHEMA_VERSION,
    deserialize_primitive,
    primitive_digest,
    serialize_primitive,
)

__all__ = [
    "EVALUATION_RESULT_SCHEMA_ID",
    "EXECUTION_SCHEMA_VERSION",
    "EXECUTION_TRACE_SCHEMA_ID",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "SerializationDiagnostic",
    "SerializationError",
    "SerializationFailure",
    "deserialize_evaluation_result",
    "deserialize_execution_trace",
    "deserialize_primitive",
    "primitive_digest",
    "serialize_artifact",
    "serialize_evaluation_result",
    "serialize_execution_trace",
    "serialize_primitive",
]
