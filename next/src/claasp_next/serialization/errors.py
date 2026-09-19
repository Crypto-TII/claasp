"""Typed diagnostics for versioned CLAASP machine formats."""

from dataclasses import dataclass
from enum import Enum


class SerializationFailure(str, Enum):
    """Stable categories for rejected serialized artifacts."""

    INVALID_JSON = "invalid_json"
    DUPLICATE_FIELD = "duplicate_field"
    UNKNOWN_SCHEMA = "unknown_schema"
    UNKNOWN_VERSION = "unknown_version"
    UNKNOWN_ARTIFACT = "unknown_artifact"
    MALFORMED_VALUE = "malformed_value"
    UNKNOWN_DOMAIN = "unknown_domain"
    UNKNOWN_COMPONENT = "unknown_component"
    DUPLICATE_IDENTITY = "duplicate_identity"
    INVALID_REFERENCE = "invalid_reference"
    TYPE_MISMATCH = "type_mismatch"
    INCONSISTENT_WIDTH = "inconsistent_width"
    UNSUPPORTED_ARTIFACT = "unsupported_artifact"


@dataclass(frozen=True, slots=True)
class SerializationDiagnostic:
    """Machine-readable serialization failure detail."""

    reason: SerializationFailure
    path: str
    message: str


class SerializationError(ValueError):
    """Reject malformed or unsupported serialized data with a typed reason."""

    def __init__(self, reason: SerializationFailure | str, message: str, *, path: str = "$") -> None:
        reason = reason if isinstance(reason, SerializationFailure) else SerializationFailure(reason)
        if not isinstance(path, str) or not path:
            raise ValueError("serialization diagnostic path must be non-empty")
        if not isinstance(message, str) or not message:
            raise ValueError("serialization diagnostic message must be non-empty")
        self.diagnostic = SerializationDiagnostic(reason, path, message)
        super().__init__(f"{reason.value} at {path}: {message}")

    @property
    def reason(self) -> SerializationFailure:
        return self.diagnostic.reason

    @property
    def path(self) -> str:
        return self.diagnostic.path


__all__ = ["SerializationDiagnostic", "SerializationError", "SerializationFailure"]
