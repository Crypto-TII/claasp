"""Solver-independent typed constraint-model provenance and applications."""

from dataclasses import dataclass
from enum import Enum


class ConstraintBackend(str, Enum):
    """Backend owning a concrete constraint encoding.

    EXAMPLES::

        >>> ConstraintBackend.SAT.value
        'sat'
    """

    SAT = "sat"
    SMT = "smt"
    MILP = "milp"
    CP = "cp"


@dataclass(frozen=True, slots=True)
class ConstraintModelProvenance:
    """Machine-readable identity of an exact component/graph encoding.

    EXAMPLES::

        >>> model = direct_model(ConstraintBackend.SAT, "M", "kind", "direct", "exact")
        >>> model.component_model
        'M'
    """

    backend: ConstraintBackend
    component_model: str
    analysis_kind: str
    encoding_name: str
    rationale: str


@dataclass(frozen=True, slots=True)
class ConstraintModelApplication:
    """Associate an encoding with the graph components it constrains.

    EXAMPLES::

        >>> model = direct_model(ConstraintBackend.SAT, "M", "kind", "direct", "exact")
        >>> ConstraintModelApplication(model, ("c0",)).component_ids
        ('c0',)
    """

    model: ConstraintModelProvenance
    component_ids: tuple[str, ...] = ()


def direct_model(
    backend: ConstraintBackend,
    component_model: str,
    analysis_kind: str,
    encoding_name: str,
    rationale: str,
) -> ConstraintModelProvenance:
    """Describe a direct exact encoding that needs no literature claim.

    EXAMPLES::

        >>> direct_model(ConstraintBackend.SAT, "M", "kind", "direct", "exact").backend
        <ConstraintBackend.SAT: 'sat'>
    """

    return ConstraintModelProvenance(
        backend, component_model, analysis_kind, encoding_name, rationale
    )


__all__ = [
    "ConstraintBackend",
    "ConstraintModelApplication",
    "ConstraintModelProvenance",
    "direct_model",
]
