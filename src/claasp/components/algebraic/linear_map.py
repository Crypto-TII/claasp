"""Matrix transformations over a scalar domain."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.graph.component import Component
from claasp.graph.port import PortLike, as_selection
from claasp.graph.value_type import ValueType


@dataclass(frozen=True, slots=True, init=False)
class LinearMap(Component):
    """Apply a row-major matrix over the input's scalar domain.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import LinearMap
        >>> LinearMap([[1, 0], [1, 1]]).evaluate(0b10)
        3
    """

    matrix: tuple[tuple[int, ...], ...]

    def __init__(
        self,
        component_input: PortLike,
        matrix: Iterable[Iterable[int]],
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        frozen_matrix = tuple(tuple(row) for row in matrix)
        if not frozen_matrix:
            raise ValueError("matrix must contain at least one row")
        width = component_input.value_type.unit_count
        if any(len(row) != width for row in frozen_matrix):
            raise ValueError(f"every matrix row must contain {width} coefficients")
        domain = component_input.value_type.domain
        for row in frozen_matrix:
            for coefficient in row:
                domain.validate(coefficient)

        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", ValueType(domain, (len(frozen_matrix),)))
        object.__setattr__(self, "matrix", frozen_matrix)
        Component.__post_init__(self)
