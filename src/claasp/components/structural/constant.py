"""Typed constant component."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.unit_array_type import UnitArrayType


@dataclass(frozen=True, slots=True, init=False)
class Constant(Component):
    """Produce a fixed homogeneous vector with a declared unit type.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Constant
        >>> Constant(8, 0x5A).evaluate()
        90
    """

    values: tuple[int, ...]

    def __init__(
        self, output_type: UnitArrayType, values: Iterable[int], component_id: str | None = None
    ) -> None:
        frozen_values = tuple(values)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", ())
        object.__setattr__(self, "output_type", output_type)
        object.__setattr__(self, "values", frozen_values)
        Component.__post_init__(self)

        if len(frozen_values) != output_type.unit_count:
            raise ValueError("constant value count must match its output type")
        for value in frozen_values:
            output_type.unit_type.validate(value)
