"""Portable analysis problem descriptions."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from claasp.analysis.constraints import Equal, FixedValue, HammingWeight, Nonzero, NotEqual
from claasp.graph import PortLike, Primitive, Selection, as_selection


@dataclass(frozen=True, slots=True, init=False)
class MinimizeWeight:
    """Request minimization of a Hamming-weight expression.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MinimizeWeight.__dataclass_params__.frozen, tuple(field.name for field in fields(MinimizeWeight)))
        (True, ('target',))
    """

    target: Selection

    def __init__(self, target: PortLike) -> None:
        object.__setattr__(self, "target", as_selection(target))


@dataclass(frozen=True, slots=True)
class AnalysisProblem:
    """A primitive, graph-level constraints, projections, and optional objective.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (AnalysisProblem.__dataclass_params__.frozen, tuple(field.name for field in fields(AnalysisProblem)))
        (True, ('primitive', 'constraints', 'projections', 'objective'))
    """

    primitive: Primitive
    constraints: tuple[object, ...]
    projections: Mapping[str, Selection]
    objective: MinimizeWeight | None = None

    def __init__(
        self,
        primitive: Primitive,
        constraints: Iterable[object] = (),
        projections: Mapping[str, PortLike] | None = None,
        objective: MinimizeWeight | None = None,
    ) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
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
        object.__setattr__(self, "primitive", primitive)
        object.__setattr__(self, "constraints", frozen_constraints)
        object.__setattr__(self, "projections", frozen_projections)
        object.__setattr__(self, "objective", objective)
