"""Immutable contracts shared by generated-source representations."""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path

from claasp_next.provenance import DriverIdentity


class SourceLanguage(str, Enum):
    """Registered languages for generated source artifacts.

    EXAMPLES::

        >>> tuple(member.value for member in SourceLanguage)
        ('python', 'c')
    """

    PYTHON = "python"
    C = "c"


class SourceStatus(str, Enum):
    """Whether a source compiler produced an executable artifact.

    EXAMPLES::

        >>> tuple(member.value for member in SourceStatus)
        ('ready', 'unsupported')
    """

    READY = "ready"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class SourceDiagnostic:
    """Typed explanation for unavailable source generation.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SourceDiagnostic.__dataclass_params__.frozen, tuple(field.name for field in fields(SourceDiagnostic)))
        (True, ('code', 'message', 'component_id'))
    """

    code: str
    message: str
    component_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not self.code:
            raise ValueError("source diagnostic code must be non-empty")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("source diagnostic message must be non-empty")


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """Deterministic generated source with graph and compiler identities.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SourceArtifact.__dataclass_params__.frozen, tuple(field.name for field in fields(SourceArtifact)))
        (True, ('language', 'source', 'filename', 'source_digest', 'primitive_digest', 'realization_identity', 'compiler'))
    """

    language: SourceLanguage
    source: str
    filename: str
    source_digest: str
    primitive_digest: str
    realization_identity: str
    compiler: DriverIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.language, SourceLanguage):
            object.__setattr__(self, "language", SourceLanguage(self.language))
        if not isinstance(self.source, str) or not self.source.endswith("\n"):
            raise ValueError("generated source must be newline-terminated text")
        if (
            not isinstance(self.filename, str) or not self.filename
            or Path(self.filename).name != self.filename
            or any(character in self.filename for character in ("\0", "\n", "\r"))
        ):
            raise ValueError("source artifact filename must be one safe basename")
        expected_suffix = ".py" if self.language is SourceLanguage.PYTHON else ".c"
        if Path(self.filename).suffix != expected_suffix:
            raise ValueError(f"source artifact filename must end in {expected_suffix}")
        actual_digest = sha256(self.source.encode("utf-8")).hexdigest()
        if self.source_digest != actual_digest:
            raise ValueError("source digest does not match generated source")
        for label, value in (("primitive digest", self.primitive_digest),):
            if not isinstance(value, str) or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        if not isinstance(self.realization_identity, str) or not self.realization_identity:
            raise ValueError("source artifact realization identity must be non-empty")
        if not isinstance(self.compiler, DriverIdentity) or self.compiler.kind.value != "compiler":
            raise ValueError("source artifact requires compiler provenance")


@dataclass(frozen=True, slots=True)
class SourceCompilationResult:
    """A ready source artifact or an explicit unsupported diagnostic.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (SourceCompilationResult.__dataclass_params__.frozen, tuple(field.name for field in fields(SourceCompilationResult)))
        (True, ('status', 'artifact', 'diagnostic'))
    """

    status: SourceStatus
    artifact: SourceArtifact | None = None
    diagnostic: SourceDiagnostic | None = None

    def __post_init__(self) -> None:
        if self.status is SourceStatus.READY and (self.artifact is None or self.diagnostic is not None):
            raise ValueError("ready source compilation requires only an artifact")
        if self.status is SourceStatus.UNSUPPORTED and (self.artifact is not None or self.diagnostic is None):
            raise ValueError("unsupported source compilation requires only a diagnostic")

    @property
    def is_ready(self) -> bool:
        """Return the is ready for this public typed contract."""

        return self.status is SourceStatus.READY


__all__ = [
    "SourceArtifact", "SourceCompilationResult", "SourceDiagnostic", "SourceLanguage", "SourceStatus",
]
