"""Affine maps on the binary encoding of extension-field elements."""

from collections.abc import Iterable
from dataclasses import dataclass

from claasp.domains import BinaryExtensionField
from claasp.graph import Component, PortLike, as_selection


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
        component_input: PortLike,
        matrix: Iterable[Iterable[int]],
        offset: int,
        component_id: str | None = None,
    ) -> None:
        component_input = as_selection(component_input)
        domain = component_input.array_type.domain
        if not isinstance(domain, BinaryExtensionField):
            raise ValueError("binary affine maps require a binary-extension-field domain")
        frozen = tuple(tuple(row) for row in matrix)
        if len(frozen) != domain.degree or any(len(row) != domain.degree for row in frozen):
            raise ValueError(f"matrix must be {domain.degree} by {domain.degree}")
        if any(coefficient not in (0, 1) for row in frozen for coefficient in row):
            raise ValueError("binary affine matrix coefficients must be zero or one")
        domain.validate(offset)
        object.__setattr__(self, "component_id", component_id)
        object.__setattr__(self, "inputs", (component_input,))
        object.__setattr__(self, "output_type", component_input.array_type)
        object.__setattr__(self, "matrix", frozen)
        object.__setattr__(self, "offset", offset)
        Component.__post_init__(self)
