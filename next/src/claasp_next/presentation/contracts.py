"""Immutable contracts shared by dependency-free presentation adapters.

The contracts qualify evidence before it reaches a table, renderer, or file.
They intentionally carry mathematical, realization, and driver provenance in
separate fields.

EXAMPLES::

    >>> from claasp_next.presentation import EvidenceClass, PresentationEvidence
    >>> evidence = PresentationEvidence(EvidenceClass.EMPIRICAL, complete=False)
    >>> evidence.is_successful_exact
    False
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from claasp_next.provenance import DriverIdentity


class EvidenceClass(str, Enum):
    """Presentation-safe classification of a result or individual value.

    EXAMPLES::

        >>> tuple(member.value for member in EvidenceClass)
        ('exact', 'proved_bound', 'empirical', 'unavailable', 'skipped', 'incomplete', 'failed')
    """

    EXACT = "exact"
    PROVED_BOUND = "proved_bound"
    EMPIRICAL = "empirical"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class Applicability(str, Enum):
    """Whether a presentation item applies to the requested semantics.

    EXAMPLES::

        >>> tuple(member.value for member in Applicability)
        ('applicable', 'inapplicable', 'unknown')
    """

    APPLICABLE = "applicable"
    INAPPLICABLE = "inapplicable"
    UNKNOWN = "unknown"


class DiagnosticCode(str, Enum):
    """Stable presentation-layer diagnostic codes.

    EXAMPLES::

        >>> tuple(member.value for member in DiagnosticCode)
        ('unsupported_result', 'unsupported_request', 'inapplicable', 'missing_evidence', 'optional_dependency_unavailable', 'invalid_format', 'unsafe_path', 'file_exists', 'render_failed')
    """

    UNSUPPORTED_RESULT = "unsupported_result"
    UNSUPPORTED_REQUEST = "unsupported_request"
    INAPPLICABLE = "inapplicable"
    MISSING_EVIDENCE = "missing_evidence"
    OPTIONAL_DEPENDENCY_UNAVAILABLE = "optional_dependency_unavailable"
    INVALID_FORMAT = "invalid_format"
    UNSAFE_PATH = "unsafe_path"
    FILE_EXISTS = "file_exists"
    RENDER_FAILED = "render_failed"


@dataclass(frozen=True, slots=True)
class PresentationDiagnostic:
    """A typed diagnostic suitable for tables and machine-readable exports.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PresentationDiagnostic.__dataclass_params__.frozen, tuple(field.name for field in fields(PresentationDiagnostic)))
        (True, ('code', 'message', 'details'))
    """

    code: DiagnosticCode
    message: str
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, DiagnosticCode):
            object.__setattr__(self, "code", DiagnosticCode(self.code))
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("diagnostic message must be a non-empty string")
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(value, str) and value for value in item)
            for item in self.details
        ):
            raise TypeError("diagnostic details must contain non-empty string pairs")
        if len({name for name, _ in self.details}) != len(self.details):
            raise ValueError("diagnostic detail names must be unique")


@dataclass(frozen=True, slots=True)
class PresentationEvidence:
    """Evidence strength, applicability, and completeness for displayed data.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PresentationEvidence.__dataclass_params__.frozen, tuple(field.name for field in fields(PresentationEvidence)))
        (True, ('classification', 'applicability', 'complete', 'diagnostic', 'bound_direction'))
    """

    classification: EvidenceClass
    applicability: Applicability = Applicability.APPLICABLE
    complete: bool = True
    diagnostic: PresentationDiagnostic | None = None
    bound_direction: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.classification, EvidenceClass):
            object.__setattr__(self, "classification", EvidenceClass(self.classification))
        if not isinstance(self.applicability, Applicability):
            object.__setattr__(self, "applicability", Applicability(self.applicability))
        if not isinstance(self.complete, bool):
            raise TypeError("evidence completeness must be Boolean")
        if self.bound_direction not in {None, "lower", "upper"}:
            raise ValueError("bound direction must be 'lower', 'upper', or None")
        if self.classification is EvidenceClass.PROVED_BOUND and self.bound_direction is None:
            raise ValueError("proved bounds require a direction")
        if (
            self.classification is not EvidenceClass.PROVED_BOUND
            and self.bound_direction is not None
        ):
            raise ValueError("only proved bounds have a bound direction")
        non_values = {
            EvidenceClass.UNAVAILABLE,
            EvidenceClass.SKIPPED,
            EvidenceClass.INCOMPLETE,
            EvidenceClass.FAILED,
        }
        if self.classification in non_values and self.diagnostic is None:
            raise ValueError(f"{self.classification.value} evidence requires a diagnostic")
        if self.classification is EvidenceClass.EXACT and not self.complete:
            raise ValueError("exact evidence must be complete")
        if (
            self.applicability is Applicability.INAPPLICABLE
            and self.classification is not EvidenceClass.UNAVAILABLE
        ):
            raise ValueError("inapplicable evidence must be classified as unavailable")

    @property
    def is_successful_exact(self) -> bool:
        """Return true only for complete, applicable, exact evidence."""

        return (
            self.classification is EvidenceClass.EXACT
            and self.applicability is Applicability.APPLICABLE
            and self.complete
        )


@dataclass(frozen=True, slots=True)
class Citation:
    """A stable citation or fixed-evidence reference.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (Citation.__dataclass_params__.frozen, tuple(field.name for field in fields(Citation)))
        (True, ('identifier', 'title', 'locator'))
    """

    identifier: str
    title: str
    locator: str | None = None

    def __post_init__(self) -> None:
        if not self.identifier or not self.title:
            raise ValueError("citation identifier and title must not be empty")


@dataclass(frozen=True, slots=True)
class MathematicalProvenance:
    """Origin and method of the mathematical or experimental claim.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MathematicalProvenance.__dataclass_params__.frozen, tuple(field.name for field in fields(MathematicalProvenance)))
        (True, ('method', 'sources', 'fixed_evidence'))
    """

    method: str
    sources: tuple[str, ...] = ()
    fixed_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.method:
            raise ValueError("mathematical method must not be empty")
        if any(not item for item in self.sources + self.fixed_evidence):
            raise ValueError("provenance references must not be empty")


@dataclass(frozen=True, slots=True)
class PrimitiveProvenance:
    """Primitive identity and selected graph realization.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PrimitiveProvenance.__dataclass_params__.frozen, tuple(field.name for field in fields(PrimitiveProvenance)))
        (True, ('primitive', 'realization'))
    """

    primitive: str
    realization: str | None = None

    def __post_init__(self) -> None:
        if not self.primitive:
            raise ValueError("primitive identity must not be empty")
        if self.realization is not None and not self.realization:
            raise ValueError("realization identity must be non-empty or None")


@dataclass(frozen=True, slots=True)
class ExecutionProvenance:
    """Execution, solver, renderer, or external-tool identity and runtime.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (ExecutionProvenance.__dataclass_params__.frozen, tuple(field.name for field in fields(ExecutionProvenance)))
        (True, ('driver', 'command', 'options', 'runtime_seconds'))
    """

    driver: DriverIdentity
    command: tuple[str, ...] = ()
    options: tuple[tuple[str, str], ...] = ()
    runtime_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.driver, DriverIdentity):
            raise TypeError("execution driver must be a DriverIdentity")
        if any(not isinstance(item, str) or not item for item in self.command):
            raise ValueError("command arguments must be non-empty strings")
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(value, str) and value for value in item)
            for item in self.options
        ):
            raise TypeError("execution options must contain non-empty string pairs")
        if tuple(sorted(self.options)) != self.options:
            raise ValueError("execution options must be sorted deterministically")
        if self.runtime_seconds is not None and self.runtime_seconds < 0:
            raise ValueError("runtime must be non-negative")


@dataclass(frozen=True, slots=True)
class ReproducibilityMetadata:
    """Dataset identities, seeds, options, and environment facts.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (ReproducibilityMetadata.__dataclass_params__.frozen, tuple(field.name for field in fields(ReproducibilityMetadata)))
        (True, ('dataset_identities', 'seeds', 'environment'))
    """

    dataset_identities: tuple[str, ...] = ()
    seeds: tuple[tuple[str, int], ...] = ()
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if any(not item for item in self.dataset_identities):
            raise ValueError("dataset identities must not be empty")
        for collection, label in ((self.seeds, "seeds"), (self.environment, "environment")):
            if tuple(sorted(collection)) != collection:
                raise ValueError(f"{label} must be sorted deterministically")
            if len({name for name, _ in collection}) != len(collection):
                raise ValueError(f"{label} names must be unique")


@dataclass(frozen=True, slots=True)
class PresentationProvenance:
    """Separated provenance carried by a presentation artifact.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PresentationProvenance.__dataclass_params__.frozen, tuple(field.name for field in fields(PresentationProvenance)))
        (True, ('mathematical', 'primitive', 'execution', 'reproducibility', 'citations'))
    """

    mathematical: MathematicalProvenance
    primitive: PrimitiveProvenance | None = None
    execution: ExecutionProvenance | None = None
    reproducibility: ReproducibilityMetadata = ReproducibilityMetadata()
    citations: tuple[Citation, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mathematical, MathematicalProvenance):
            raise TypeError("mathematical provenance has the wrong type")
        if self.primitive is not None and not isinstance(self.primitive, PrimitiveProvenance):
            raise TypeError("primitive provenance has the wrong type")
        if self.execution is not None and not isinstance(self.execution, ExecutionProvenance):
            raise TypeError("execution provenance has the wrong type")
        if not isinstance(self.reproducibility, ReproducibilityMetadata):
            raise TypeError("reproducibility metadata has the wrong type")
        if any(not isinstance(item, Citation) for item in self.citations):
            raise TypeError("citations must contain Citation values")
