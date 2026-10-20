"""Shared validation for homogeneous algebraic components."""

from collections.abc import Iterable

from claasp.graph.unit_array import Selection, UnitArrayLike, as_selection
from claasp.graph.unit_array_type import UnitArrayType


def normalize_inputs(inputs: tuple[UnitArrayLike, ...]) -> tuple[Selection, ...]:
    return tuple(as_selection(item) for item in inputs)


def require_homogeneous_inputs(inputs: tuple[Selection, ...], operation: str) -> UnitArrayType:
    if not inputs:
        raise ValueError(f"{operation} requires at least one input")
    if any(not isinstance(item, Selection) for item in inputs):
        raise TypeError(f"every {operation} input must be a Selection")
    array_type = inputs[0].array_type
    if any(item.array_type != array_type for item in inputs[1:]):
        raise ValueError(f"{operation} inputs must have identical array types")
    return array_type


def normalize_operand_arguments(
    arguments: tuple[UnitArrayLike | Iterable[UnitArrayLike] | str, ...],
    component_id: str | None,
) -> tuple[tuple[Selection, ...], str | None]:
    """Accept separate operands or one iterable, with an optional legacy ID."""
    if arguments and isinstance(arguments[-1], str):
        if component_id is not None:
            raise TypeError("component_id was supplied twice")
        component_id = arguments[-1]
        arguments = arguments[:-1]
    if len(arguments) == 1 and not isinstance(arguments[0], (UnitArrayLike, str)):
        arguments = tuple(arguments[0])
    operands = []
    for argument in arguments:
        if not isinstance(argument, UnitArrayLike):
            raise TypeError("every component input must be a UnitArray or Selection")
        operands.append(argument)
    return normalize_inputs(tuple(operands)), component_id
