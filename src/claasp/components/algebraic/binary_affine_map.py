"""Affine maps on the binary encoding of extension-field elements."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.graph import Component, UnitArrayLike, as_selection
from claasp.unit_types import BinaryExtensionField


@dataclass(frozen=True, slots=True, init=False)
class BinaryAffineMap(Component):
    """Apply the same GF(2) affine map independently to every input unit.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import BinaryAffineMap
        >>> BinaryAffineMap(offset=3).evaluate(10)
        9
    """

    matrix: tuple[tuple[int, ...], ...]
    offset: int

    def __init__(
        self,
        component_input: UnitArrayLike,
        matrix: Iterable[Iterable[int]],
        offset: int,
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        unit_type = component_input.array_type.unit_type
        if not isinstance(unit_type, BinaryExtensionField):
            raise ValueError("binary affine maps require a binary-extension-field unit type")
        frozen = tuple(tuple(row) for row in matrix)
        if len(frozen) != unit_type.degree or any(len(row) != unit_type.degree for row in frozen):
            raise ValueError(f"matrix must be {unit_type.degree} by {unit_type.degree}")
        if any(coefficient not in (0, 1) for row in frozen for coefficient in row):
            raise ValueError("binary affine matrix coefficients must be zero or one")
        unit_type.validate(offset)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.array_type)
        object.__setattr__(self, "matrix", frozen)
        object.__setattr__(self, "offset", offset)
        Component.__post_init__(self)
