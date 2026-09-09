"""Domain-polymorphic power map."""

from dataclasses import dataclass

from claasp_next.core.component import Component
from claasp_next.core.port import Selection


@dataclass(frozen=True, slots=True, init=False)
class Power(Component):
    """Raise every selected scalar to a fixed positive exponent."""

    exponent: int

    def __init__(self, component_id: str, component_input: Selection, exponent: int) -> None:
        if not isinstance(component_input, Selection):
            raise TypeError("power input must be a Selection")
        if not isinstance(exponent, int) or isinstance(exponent, bool):
            raise TypeError("exponent must be an integer")
        if exponent <= 0:
            raise ValueError("exponent must be positive")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        object.__setattr__(self, "exponent", exponent)
        Component.__post_init__(self)
