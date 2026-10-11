"""Typed identity component."""

from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.unit_array import UnitArrayLike, as_selection


@dataclass(frozen=True, slots=True, init=False)
class Identity(Component):
    """Copy a logical-unit selection without changing its unit type.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Identity
        >>> Identity(16).evaluate(0xCAFE)
        51966
    """

    def __init__(self, component_input: UnitArrayLike, component_id: str | None = None) -> None:
        component_input = as_selection(component_input)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.array_type)
        Component.__post_init__(self)
