"""Domain-polymorphic multiplication."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.components.algebraic._validation import (
    normalize_inputs,
    require_homogeneous_inputs,
)
from claasp.graph.component import Component
from claasp.graph.port import Selection


@dataclass(frozen=True, slots=True, init=False)
class Multiply(Component):
    """Multiply two or more homogeneous vectors component-wise.

    EXAMPLES::

        >>> from claasp import PrimeField
        >>> from claasp.primitives.single_component_primitives import Multiply as MultiplyPrimitive
        >>> MultiplyPrimitive(domain=PrimeField(17)).evaluate(5, 7)
        1
    """

    def __init__(
        self, component_inputs: Iterable[Selection], component_id: str | None = None
    ) -> None:
        frozen_inputs = normalize_inputs(tuple(component_inputs))
        if len(frozen_inputs) < 2:
            raise ValueError("multiplication requires at least two inputs")
        output_type = require_homogeneous_inputs(frozen_inputs, "multiplication")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", frozen_inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
