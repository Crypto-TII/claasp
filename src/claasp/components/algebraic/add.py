"""UnitType-polymorphic addition."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.components.algebraic._validation import (
    normalize_operand_arguments,
    require_homogeneous_inputs,
)
from claasp.graph.component import Component
from claasp.graph.unit_array import UnitArrayLike


@dataclass(frozen=True, slots=True, init=False)
class Add(Component):
    """Add two or more homogeneous vectors component-wise.

    Pass inputs as separate arguments, or as one iterable.
    ``component_id`` can be supplied by keyword.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Add as AddPrimitive
        >>> AddPrimitive().evaluate(1, 1)
        0
    """

    def __init__(
        self,
        *component_inputs: UnitArrayLike | Iterable[UnitArrayLike] | str,
        component_id: str | None = None,
    ) -> None:
        frozen_inputs, component_id = normalize_operand_arguments(component_inputs, component_id)
        if len(frozen_inputs) < 2:
            raise ValueError("addition requires at least two inputs")
        output_type = require_homogeneous_inputs(frozen_inputs, "addition")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", frozen_inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
