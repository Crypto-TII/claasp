"""Typed identity component."""

from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.port import PortLike, as_selection


@dataclass(frozen=True, slots=True, init=False)
class Identity(Component):
    """Copy a logical-unit selection without changing its domain.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Identity
        >>> Identity(16).evaluate(0xCAFE)
        51966
    """

    def __init__(self, component_input: PortLike, component_id: str | None = None) -> None:
        component_input = as_selection(component_input)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        Component.__post_init__(self)
