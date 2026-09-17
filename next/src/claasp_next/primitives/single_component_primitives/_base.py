"""Small authoring helpers shared by one-component primitive examples."""

from collections.abc import Sequence

from claasp_next.domains import Bit, Word
from claasp_next.graph import PrimitiveKind, ValueType


def positive(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def positive_or_default(value: int | None, default: int, name: str) -> int:
    """Use a documented default or validate an explicitly supplied size."""

    return default if value is None else positive(value, name)


def lookup_table_or_identity(
    lookup_table: Sequence[int] | None, input_bit_size: int
) -> list[int]:
    """Return the supplied lookup table or the identity table of this width."""

    return (
        list(range(1 << input_bit_size)) if lookup_table is None else list(lookup_table)
    )


def lookup_table_kind(
    table: Sequence[int], input_bit_size: int, output_bit_size: int
) -> PrimitiveKind:
    """Classify a lookup as a permutation exactly when it is bijective."""

    is_bijective = output_bit_size == input_bit_size and sorted(table) == list(
        range(1 << input_bit_size)
    )
    return PrimitiveKind.PERMUTATION if is_bijective else PrimitiveKind.FUNCTION


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
