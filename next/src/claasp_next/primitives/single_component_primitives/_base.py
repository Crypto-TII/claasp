"""Shared validation helpers for one-component primitive modules."""

from claasp_next.domains import BinaryExtensionField, Word
from claasp_next.domains.validation import is_irreducible_binary_polynomial
from claasp_next.graph import ValueType
from claasp_next.utils import binary_field_multiply, binary_field_power


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


def inverse_mapping(destination_by_source: tuple[int, ...]) -> tuple[int, ...]:
    if sorted(destination_by_source) != list(range(len(destination_by_source))):
        raise ValueError("permutation_description must be a permutation")
    return tuple(destination_by_source.index(destination) for destination in range(len(destination_by_source)))


def first_irreducible(degree: int) -> int:
    for polynomial in range((1 << degree) | 1, 1 << (degree + 1), 2):
        if is_irreducible_binary_polynomial(polynomial, degree):
            return polynomial
    raise ValueError(f"no irreducible polynomial found for degree {degree}")


def binary_matrix_is_invertible(matrix) -> bool:
    frozen = [list(row) for row in matrix]
    if not frozen or len(frozen) != len(frozen[0]) or any(len(row) != len(frozen) for row in frozen):
        return False
    rank = 0
    for column in range(len(frozen)):
        pivot = next((row for row in range(rank, len(frozen)) if frozen[row][column]), None)
        if pivot is None:
            continue
        frozen[rank], frozen[pivot] = frozen[pivot], frozen[rank]
        for row in range(len(frozen)):
            if row != rank and frozen[row][column]:
                frozen[row] = [left ^ right for left, right in zip(frozen[row], frozen[rank])]
        rank += 1
    return rank == len(frozen)


def field_matrix_is_invertible(matrix, field: BinaryExtensionField) -> bool:
    frozen = [list(row) for row in matrix]
    if not frozen or len(frozen) != len(frozen[0]) or any(len(row) != len(frozen) for row in frozen):
        return False
    rank = 0
    for column in range(len(frozen)):
        pivot = next((row for row in range(rank, len(frozen)) if frozen[row][column]), None)
        if pivot is None:
            continue
        frozen[rank], frozen[pivot] = frozen[pivot], frozen[rank]
        inverse = binary_field_power(field, frozen[rank][column], (1 << field.degree) - 2)
        frozen[rank] = [binary_field_multiply(field, value, inverse) for value in frozen[rank]]
        for row in range(len(frozen)):
            factor = frozen[row][column]
            if row != rank and factor:
                frozen[row] = [
                    left ^ binary_field_multiply(field, factor, right)
                    for left, right in zip(frozen[row], frozen[rank])
                ]
        rank += 1
    return rank == len(frozen)
