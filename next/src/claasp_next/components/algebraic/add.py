"""Domain-polymorphic addition."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp_next.components.algebraic._validation import require_homogeneous_inputs
from claasp_next.core.component import Component
from claasp_next.core.port import Selection


@dataclass(frozen=True, slots=True, init=False)
class Add(Component):
    """Add two or more homogeneous vectors component-wise."""

    def __init__(self, component_id: str, component_inputs: Iterable[Selection]) -> None:
        frozen_inputs = tuple(component_inputs)
        if len(frozen_inputs) < 2:
            raise ValueError("addition requires at least two inputs")
        output_type = require_homogeneous_inputs(frozen_inputs, "addition")
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", frozen_inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
