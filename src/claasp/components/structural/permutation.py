"""Domain-neutral logical-unit permutation."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.port import PortLike, as_selection


@dataclass(frozen=True, slots=True, init=False)
class Permutation(Component):
    """Reorder a selection using ``output[i] = input[mapping[i]]``.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import Permutation
        >>> Permutation([3, 2, 1, 0]).evaluate(0b1100)
        3
    """

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
        """Reverse all logical units in a component input.

        EXAMPLES::

            >>> from claasp import Bit, Primitive, ValueType
            >>> from claasp.components import Permutation
            >>> graph = Primitive("reverse", {"x": ValueType(Bit(), (4,))})
            >>> _ = graph.add_round()
            >>> Permutation.reverse(graph.input("x")).mapping
            (3, 2, 1, 0)
        """

        size = as_selection(component_input).value_type.unit_count
        return cls(component_input, reversed(range(size)), component_id)
