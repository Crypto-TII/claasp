"""Portable analysis problem descriptions."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from claasp_next.analysis.constraints import Equal, FixedValue, HammingWeight, Nonzero, NotEqual
from claasp_next.core import Cipher, PortLike, Selection, as_selection


@dataclass(frozen=True, slots=True, init=False)
class MinimizeWeight:
    """Request minimization of a Hamming-weight expression."""

    target: Selection

    def __init__(self, target: PortLike) -> None:
        object.__setattr__(self, "target", as_selection(target))


@dataclass(frozen=True, slots=True)
class AnalysisProblem:
    """A cipher, graph-level constraints, projections, and optional objective."""

    cipher: Cipher
    constraints: tuple[object, ...]
    projections: Mapping[str, Selection]
    objective: MinimizeWeight | None = None

    def __init__(
        self,
        cipher: Cipher,
        constraints: Iterable[object] = (),
        projections: Mapping[str, PortLike] | None = None,
        objective: MinimizeWeight | None = None,
    ) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        frozen_constraints = tuple(constraints)
        constraint_types = (FixedValue, Equal, NotEqual, Nonzero, HammingWeight)
        if any(not isinstance(item, constraint_types) for item in frozen_constraints):
            raise TypeError("unsupported analysis constraint")
        frozen_projections = {
            name: as_selection(target) for name, target in (projections or {}).items()
        }
        if any(not isinstance(name, str) or not name for name in frozen_projections):
            raise ValueError("projection names must be non-empty strings")
        if objective is not None and not isinstance(objective, MinimizeWeight):
            raise TypeError("objective must be MinimizeWeight or None")
        object.__setattr__(self, "cipher", cipher)
        object.__setattr__(self, "constraints", frozen_constraints)
        object.__setattr__(self, "projections", frozen_projections)
        object.__setattr__(self, "objective", objective)
