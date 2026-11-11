"""Versioned, dependency-free CLAASP serialization."""

from claasp._catalogue_metadata import _entry
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


__catalogue__ = (
    _entry(
        "representation",
        serialize_primitive,
        name="primitive_serialization",
        kind="serialization",
        components=(
            "Add",
            "BinaryAffineMap",
            "BitVectorSBox",
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "FeedbackRegister",
            "IDEAMultiply",
            "Identity",
            "LinearMap",
            "ModularAdd",
            "ModularMultiply",
            "ModularSubtract",
            "Multiply",
            "Permutation",
            "Power",
            "Rotate",
            "SBox",
            "Shift",
            "VariableRotate",
            "VariableShift",
            "Xor",
        ),
        domains=("BinaryExtensionField", "Bit", "PrimeField", "Word"),
        drivers=(),
        scope="generic_graph",
    ),
    _entry(
        "representation",
        serialize_artifact,
        name="execution_artifact_serialization",
        kind="serialization",
        components=(),
        domains=("BinaryExtensionField", "Bit", "PrimeField", "Word"),
        drivers=(),
        scope="result",
    ),
)
