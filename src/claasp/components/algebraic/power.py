"""UnitType-polymorphic power map."""

from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.unit_array import UnitArrayLike, as_selection


@dataclass(frozen=True, slots=True, init=False)
class Power(Component):
    """Raise every selected scalar to a fixed positive exponent.

    EXAMPLES::

        >>> from claasp.unit_types import PrimeField
        >>> from claasp.primitives.single_component_primitives import Power as PowerPrimitive
        >>> PowerPrimitive(3, unit_type=PrimeField(17)).evaluate(5)
        6
    """

    exponent: int

    def __init__(
        self, component_input: UnitArrayLike, exponent: int, component_id: str | None = None
    ) -> None:
        component_input = as_selection(component_input)
        if not isinstance(exponent, int) or isinstance(exponent, bool):
            raise TypeError("exponent must be an integer")
        if exponent <= 0:
            raise ValueError("exponent must be positive")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.array_type)
        object.__setattr__(self, "exponent", exponent)
        Component.__post_init__(self)
