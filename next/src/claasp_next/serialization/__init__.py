"""Versioned, dependency-free CLAASP serialization."""

from claasp_next.serialization.errors import (
    SerializationDiagnostic, SerializationError, SerializationFailure,
)
from claasp_next.serialization.primitive import (
    SCHEMA_ID, SCHEMA_VERSION, deserialize_primitive, primitive_digest, serialize_primitive,
)

__all__ = [
    "SCHEMA_ID", "SCHEMA_VERSION", "SerializationDiagnostic", "SerializationError",
    "SerializationFailure", "deserialize_primitive", "primitive_digest", "serialize_primitive",
]
