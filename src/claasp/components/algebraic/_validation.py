"""Shared validation for homogeneous algebraic components."""

from claasp.graph.array_type import ArrayType
from claasp.graph.port import PortLike, Selection, as_selection


def normalize_inputs(inputs: tuple[PortLike, ...]) -> tuple[Selection, ...]:
    return tuple(as_selection(item) for item in inputs)


def require_homogeneous_inputs(inputs: tuple[Selection, ...], operation: str) -> ArrayType:
    if not inputs:
        raise ValueError(f"{operation} requires at least one input")
    if any(not isinstance(item, Selection) for item in inputs):
        raise TypeError(f"every {operation} input must be a Selection")
    array_type = inputs[0].array_type
    if any(item.array_type != array_type for item in inputs[1:]):
        raise ValueError(f"{operation} inputs must have identical array types")
    return array_type
