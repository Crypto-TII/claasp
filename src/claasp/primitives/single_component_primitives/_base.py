"""Small authoring helpers shared by one-component primitive examples."""

from claasp.domains import Bit, Word
from claasp.graph import ValueType


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
    value_type = ValueType(Word(word_bit_size), (1,))
    return {f"input_{index}": value_type for index in range(number_of_inputs)}


def algebraic_inputs(domain, unit_count: int, number_of_inputs: int):
    domain = Bit() if domain is None else domain
    positive(unit_count, "unit_count")
    if (
        not isinstance(number_of_inputs, int)
        or isinstance(number_of_inputs, bool)
        or number_of_inputs < 2
    ):
        raise ValueError("number_of_inputs must be at least 2")
    value_type = ValueType(domain, (unit_count,))
    return {f"input_{index}": value_type for index in range(number_of_inputs)}
