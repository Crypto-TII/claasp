"""Shared validation helpers for one-component primitive modules."""

from claasp_next.domains import Word
from claasp_next.graph import ValueType


def positive(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def word_inputs(word_bit_size: int, number_of_inputs: int):
    positive(word_bit_size, "word_bit_size")
    if not isinstance(number_of_inputs, int) or isinstance(number_of_inputs, bool) or number_of_inputs < 2:
        raise ValueError("number_of_inputs must be at least 2")
    value_type = ValueType(Word(word_bit_size), (1,))
    return {f"input_{index}": value_type for index in range(number_of_inputs)}
