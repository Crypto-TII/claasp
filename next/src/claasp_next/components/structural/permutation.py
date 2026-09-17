"""Domain-neutral logical-unit permutation."""

from dataclasses import dataclass
from collections.abc import Iterable

from claasp_next.graph.component import Component
from claasp_next.graph.port import PortLike, as_selection


@dataclass(frozen=True, slots=True, init=False)
class Permutation(Component):
    """Reorder a selection using ``output[i] = input[mapping[i]]``."""

    mapping: tuple[int, ...]

    def __init__(
        self,
        component_input: PortLike,
        mapping: Iterable[int],
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        frozen_mapping = tuple(mapping)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        object.__setattr__(self, "mapping", frozen_mapping)
        Component.__post_init__(self)

        size = component_input.value_type.unit_count
        if len(frozen_mapping) != size or set(frozen_mapping) != set(range(size)):
            raise ValueError(f"mapping must be a permutation of range({size})")

    @classmethod
    def reverse(
        cls,
        component_input: PortLike,
        component_id: str | None = None,
    ) -> "Permutation":
        """Reverse all logical units in a component input."""

        size = as_selection(component_input).value_type.unit_count
        return cls(component_input, reversed(range(size)), component_id)
