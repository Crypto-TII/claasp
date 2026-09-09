"""Domain-neutral logical-unit permutation."""

from dataclasses import dataclass
from collections.abc import Iterable

from claasp_next.core.component import Component
from claasp_next.core.port import Selection


@dataclass(frozen=True, slots=True, init=False)
class Permutation(Component):
    """Reorder a selection using ``output[i] = input[mapping[i]]``."""

    mapping: tuple[int, ...]

    def __init__(
        self,
        component_id: str,
        component_input: Selection,
        mapping: Iterable[int],
    ) -> None:
        frozen_mapping = tuple(mapping)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.value_type)
        object.__setattr__(self, "mapping", frozen_mapping)
        Component.__post_init__(self)

        size = component_input.value_type.unit_count
        if len(frozen_mapping) != size or set(frozen_mapping) != set(range(size)):
            raise ValueError(f"mapping must be a permutation of range({size})")
