"""Domain-neutral concatenation."""

from dataclasses import dataclass
from collections.abc import Iterable

from claasp_next.graph.component import Component
from claasp_next.graph.port import PortLike, Selection, as_selection
from claasp_next.graph.value_type import ValueType


@dataclass(frozen=True, slots=True, init=False)
class Concatenate(Component):
    """Concatenate homogeneous selections in input order."""

    def __init__(self, component_inputs: Iterable[PortLike], component_id: str | None = None) -> None:
        frozen_inputs = tuple(as_selection(item) for item in component_inputs)
        if not frozen_inputs:
            raise ValueError("concatenation requires at least one input")
        if any(not isinstance(item, Selection) for item in frozen_inputs):
            raise TypeError("every concatenation input must be a Selection")

        domain = frozen_inputs[0].value_type.domain
        if any(item.value_type.domain != domain for item in frozen_inputs[1:]):
            raise ValueError("concatenation inputs must use the same domain")

        output_type = ValueType(domain, (sum(item.value_type.unit_count for item in frozen_inputs),))
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", frozen_inputs)
        object.__setattr__(self, "output_type", output_type)
        Component.__post_init__(self)
