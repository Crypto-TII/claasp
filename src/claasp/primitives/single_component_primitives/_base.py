"""Small authoring helpers shared by one-component primitive examples."""

from claasp.graph import UnitArrayType
from claasp.unit_types import Bit, Word


def positive(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def word_inputs(word_bit_size: int, number_of_inputs: int):
    positive(word_bit_size, "word_bit_size")
    if (
        not isinstance(number_of_inputs, int)
        or isinstance(number_of_inputs, bool)
        or number_of_inputs < 2
    ):
        raise ValueError("number_of_inputs must be at least 2")
    array_type = UnitArrayType(Word(word_bit_size), (1,))
    return {f"input_{index}": array_type for index in range(number_of_inputs)}


def algebraic_inputs(unit_type, unit_count: int, number_of_inputs: int):
    unit_type = Bit() if unit_type is None else unit_type
    positive(unit_count, "unit_count")
    if (
        not isinstance(number_of_inputs, int)
        or isinstance(number_of_inputs, bool)
        or number_of_inputs < 2
    ):
        raise ValueError("number_of_inputs must be at least 2")
    array_type = UnitArrayType(unit_type, (unit_count,))
    return {f"input_{index}": array_type for index in range(number_of_inputs)}
