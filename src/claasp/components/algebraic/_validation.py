"""Shared validation for homogeneous algebraic components."""

from claasp.graph.port import PortLike, Selection, as_selection
from claasp.graph.value_type import ValueType


def normalize_inputs(inputs: tuple[PortLike, ...]) -> tuple[Selection, ...]:
    return tuple(as_selection(item) for item in inputs)


def require_homogeneous_inputs(inputs: tuple[Selection, ...], operation: str) -> ValueType:
    if not inputs:
        raise ValueError(f"{operation} requires at least one input")
    if any(not isinstance(item, Selection) for item in inputs):
        raise TypeError(f"every {operation} input must be a Selection")
    value_type = inputs[0].value_type
    if any(item.value_type != value_type for item in inputs[1:]):
        raise ValueError(f"{operation} inputs must have identical value types")
    return value_type
