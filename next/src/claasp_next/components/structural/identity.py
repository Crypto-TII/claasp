"""Typed identity component."""

from dataclasses import dataclass

from claasp_next.core.component import Component
from claasp_next.core.port import Selection


@dataclass(frozen=True, slots=True, init=False)
class Identity(Component):
    """Copy a logical-unit selection without changing its domain."""

    def __init__(self, component_id: str, component_input: Selection) -> None:
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        Component.__post_init__(self)
