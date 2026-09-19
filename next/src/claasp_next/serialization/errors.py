"""Typed diagnostics for versioned CLAASP machine formats."""

from dataclasses import dataclass
from enum import Enum


class SerializationFailure(str, Enum):
    """Stable categories for rejected serialized artifacts.

    EXAMPLES::

        >>> from claasp_next import SerializationFailure
        >>> SerializationFailure.INVALID_JSON.value
        'invalid_json'
    """

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
    """Machine-readable serialization failure detail.

    EXAMPLES::

        >>> from claasp_next import SerializationDiagnostic, SerializationFailure
        >>> SerializationDiagnostic(SerializationFailure.INVALID_JSON, "$", "bad input").path
        '$'
    """

    reason: SerializationFailure
    path: str
    message: str


class SerializationError(ValueError):
    """Reject malformed or unsupported serialized data with a typed reason.

    EXAMPLES::

        >>> from claasp_next import SerializationError, SerializationFailure
        >>> error = SerializationError(SerializationFailure.INVALID_JSON, "bad input", path="$.value")
        >>> (error.reason, error.path, str(error))
        (<SerializationFailure.INVALID_JSON: 'invalid_json'>, '$.value', 'invalid_json at $.value: bad input')
    """

    def __init__(
        self, reason: SerializationFailure | str, message: str, *, path: str = "$"
    ) -> None:
        reason = (
            reason if isinstance(reason, SerializationFailure) else SerializationFailure(reason)
        )
        if not isinstance(path, str) or not path:
            raise ValueError("serialization diagnostic path must be non-empty")
        if not isinstance(message, str) or not message:
            raise ValueError("serialization diagnostic message must be non-empty")
        self.diagnostic = SerializationDiagnostic(reason, path, message)
        super().__init__(f"{reason.value} at {path}: {message}")

    @property
    def reason(self) -> SerializationFailure:
        """Return the stable machine-readable failure category."""
        return self.diagnostic.reason

    @property
    def path(self) -> str:
        """Return the JSON-style path at which validation failed."""
        return self.diagnostic.path


__all__ = ["SerializationDiagnostic", "SerializationError", "SerializationFailure"]
