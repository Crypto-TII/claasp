"""Solver-independent typed constraint representation contracts."""

from dataclasses import dataclass
from enum import Enum


class ConstraintBackend(str, Enum):
    """Constraint backends that own concrete encodings.

    EXAMPLES::

        >>> tuple(backend.value for backend in ConstraintBackend)
        ('sat', 'smt', 'milp', 'cp')
    """

    SAT = "sat"
    SMT = "smt"
    MILP = "milp"
    CP = "cp"


class ConstraintReferenceStatus(str, Enum):
    """Review state of an encoding's literature correspondence.

    EXAMPLES::

        >>> tuple(status.value for status in ConstraintReferenceStatus)
        ('VERIFIED', 'N/A', 'TBD')
    """

    VERIFIED = "VERIFIED"
    NOT_APPLICABLE = "N/A"
    TO_BE_DETERMINED = "TBD"


@dataclass(frozen=True, slots=True)
class ConstraintModelProvenance:
    """Identity and reference status declared by one concrete encoding.

    ``VERIFIED`` is reserved for a checked primary source with a precise
    locator. Direct encodings use ``N/A``; unaudited correspondences use
    ``TBD`` and explain what remains to be checked.

    EXAMPLES::

        >>> record = ConstraintModelProvenance(
        ...     ConstraintBackend.SAT, "SBoxFunctionalSATModel", "functional",
        ...     "exhaustive truth-table clauses", ConstraintReferenceStatus.NOT_APPLICABLE,
        ...     rationale="Direct exhaustive encoding.",
        ... )
        >>> record.compact_reference
        'N/A — Direct exhaustive encoding.'
    """

    backend: ConstraintBackend
    component_model: str
    analysis_kind: str
    encoding_name: str
    reference_status: ConstraintReferenceStatus
    reference_identifier: str | None = None
    reference_title: str | None = None
    source_locator: str | None = None
    rationale: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.backend, ConstraintBackend):
            raise TypeError("backend must be a ConstraintBackend")
        if not isinstance(self.reference_status, ConstraintReferenceStatus):
            raise TypeError("reference_status must be a ConstraintReferenceStatus")
        for name in ("component_model", "analysis_kind", "encoding_name"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a nonempty string")
        optional = (
            self.reference_identifier,
            self.reference_title,
            self.source_locator,
            self.rationale,
        )
        if any(
            value is not None and (not isinstance(value, str) or not value.strip())
            for value in optional
        ):
            raise ValueError("optional provenance text must be nonempty or None")
        if self.reference_status is ConstraintReferenceStatus.VERIFIED:
            if not all((self.reference_identifier, self.reference_title, self.source_locator)):
                raise ValueError("VERIFIED provenance requires identifier, title, and locator")
            identifier = self.reference_identifier or ""
            if not (
                identifier.startswith(("https://", "http://", "doi:"))
                or identifier.startswith("10.")
            ):
                raise ValueError("VERIFIED identifier must be a primary-source URL or DOI")
        elif not self.rationale:
            raise ValueError("N/A and TBD provenance require a rationale")

    @property
    def compact_reference(self) -> str:
        """Return the concise value shown beside a modeled component."""

        if self.reference_status is ConstraintReferenceStatus.VERIFIED:
            return f"{self.reference_identifier} ({self.source_locator})"
        return f"{self.reference_status.value} — {self.rationale}"


@dataclass(frozen=True, slots=True)
class ConstraintModelApplication:
    """Apply one encoding declaration to concrete graph components.

    EXAMPLES::

        >>> record = ConstraintModelProvenance(
        ...     ConstraintBackend.CP, "TableCPModel", "xor_differential",
        ...     "exhaustive table", ConstraintReferenceStatus.NOT_APPLICABLE,
        ...     rationale="Generated exhaustively.",
        ... )
        >>> ConstraintModelApplication(record, ("sbox_0",)).component_ids
        ('sbox_0',)
    """

    model: ConstraintModelProvenance
    component_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.model, ConstraintModelProvenance):
            raise TypeError("model must be ConstraintModelProvenance")
        if any(not isinstance(item, str) or not item for item in self.component_ids):
            raise ValueError("component IDs must be nonempty strings")
        if len(set(self.component_ids)) != len(self.component_ids):
            raise ValueError("component IDs must be unique within one application")


def _direct_model(
    backend: ConstraintBackend,
    component_model: str,
    analysis_kind: str,
    encoding_name: str,
    rationale: str,
) -> ConstraintModelProvenance:
    """Construct an explicit ``N/A`` declaration for a direct encoding."""

    return ConstraintModelProvenance(
        backend,
        component_model,
        analysis_kind,
        encoding_name,
        ConstraintReferenceStatus.NOT_APPLICABLE,
        rationale=rationale,
    )


def _unaudited_model(
    backend: ConstraintBackend,
    component_model: str,
    analysis_kind: str,
    encoding_name: str,
    rationale: str,
) -> ConstraintModelProvenance:
    """Construct an explicit ``TBD`` declaration pending literature review."""

    return ConstraintModelProvenance(
        backend,
        component_model,
        analysis_kind,
        encoding_name,
        ConstraintReferenceStatus.TO_BE_DETERMINED,
        rationale=rationale,
    )


__all__ = [
    "ConstraintBackend",
    "ConstraintModelApplication",
    "ConstraintModelProvenance",
    "ConstraintReferenceStatus",
]
