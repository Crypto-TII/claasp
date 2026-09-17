"""Metadata and deterministic selection for primitive graph realizations."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class RealizationMaturity(str, Enum):
    """Review status of one graph realization."""

    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    LEGACY_REGRESSION = "legacy_regression"


class RealizationSelectionPolicy(str, Enum):
    """How capability selection resolves multiple compatible graphs."""

    PREFERRED = "preferred"
    UNIQUE = "unique"


class RealizationSelectionError(ValueError):
    """Base class for realization-selection failures."""


class UnsupportedRealizationError(RealizationSelectionError):
    """No realization satisfies the requested name or capabilities."""


class AmbiguousRealizationError(RealizationSelectionError):
    """A declared selection policy cannot choose one realization."""


def _names(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError(f"{label} must be an iterable of names, not a string")
    frozen = frozenset(values)
    if any(not isinstance(item, str) or not item for item in frozen):
        raise ValueError(f"{label} entries must be non-empty strings")
    return frozen


@dataclass(frozen=True, slots=True)
class RealizationDescriptor:
    """Stable identity, capabilities, structure, maturity, and provenance."""

    name: str
    capabilities: frozenset[str]
    structure: frozenset[str]
    description: str
    maturity: RealizationMaturity = RealizationMaturity.STABLE
    provenance: tuple[str, ...] = ()
    priority: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("a realization requires a non-empty name")
        if not isinstance(self.description, str) or not self.description:
            raise ValueError("a realization requires a non-empty description")
        object.__setattr__(self, "capabilities", _names(self.capabilities, "capabilities"))
        object.__setattr__(self, "structure", _names(self.structure, "structural features"))
        if not isinstance(self.maturity, RealizationMaturity):
            object.__setattr__(self, "maturity", RealizationMaturity(self.maturity))
        frozen_provenance = tuple(self.provenance)
        if any(not isinstance(item, str) or not item for item in frozen_provenance):
            raise ValueError("realization provenance entries must be non-empty strings")
        object.__setattr__(self, "provenance", frozen_provenance)
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise TypeError("realization priority must be an integer")

    def supports(self, requirements: Iterable[str]) -> bool:
        """Return whether all requested capabilities are declared."""

        return _names(requirements, "capability requirements") <= self.capabilities


def select_realization(
    descriptors: Iterable[RealizationDescriptor],
    requirements: Iterable[str],
    *,
    policy: RealizationSelectionPolicy | str = RealizationSelectionPolicy.PREFERRED,
    primitive_name: str = "primitive",
) -> RealizationDescriptor:
    """Select a compatible descriptor under an explicit deterministic policy."""

    requested = _names(requirements, "capability requirements")
    selected_policy = policy if isinstance(policy, RealizationSelectionPolicy) else RealizationSelectionPolicy(policy)
    matches = tuple(item for item in descriptors if item.supports(requested))
    rendered = tuple(sorted(requested))
    if not matches:
        raise UnsupportedRealizationError(
            f"no {primitive_name} realization supports capabilities {rendered}"
        )
    if selected_policy is RealizationSelectionPolicy.UNIQUE:
        if len(matches) != 1:
            names = tuple(item.name for item in matches)
            raise AmbiguousRealizationError(
                f"{primitive_name} capability request {rendered} matches {names} under unique policy"
            )
        return matches[0]
    best_priority = min(item.priority for item in matches)
    preferred = tuple(item for item in matches if item.priority == best_priority)
    if len(preferred) != 1:
        names = tuple(item.name for item in preferred)
        raise AmbiguousRealizationError(
            f"{primitive_name} capability request {rendered} has equal-priority matches {names}"
        )
    return preferred[0]
