"""Validated finite lookup-table descriptions."""

from collections.abc import Iterable
from dataclasses import dataclass


def _positive_bit_size(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True, slots=True, init=False)
class LookupTable:
    """An immutable lookup table with explicit input and output widths.

    EXAMPLES::

        >>> from claasp_next.components import LookupTable
        >>> table = LookupTable([3, 2, 1, 0], input_bit_size=2)
        >>> table.is_bijective()
        True
    """

    values: tuple[int, ...]
    input_bit_size: int
    output_bit_size: int

    def __init__(
        self,
        values: Iterable[int],
        input_bit_size: int,
        output_bit_size: int | None = None,
    ) -> None:
        input_bit_size = _positive_bit_size(input_bit_size, "input_bit_size")
        if output_bit_size is None:
            output_bit_size = input_bit_size
        output_bit_size = _positive_bit_size(output_bit_size, "output_bit_size")

        frozen_values = tuple(values)
        expected_size = 1 << input_bit_size
        if len(frozen_values) != expected_size:
            raise ValueError(f"lookup table must contain {expected_size} entries")
        output_limit = 1 << output_bit_size
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < output_limit
            for value in frozen_values
        ):
            raise ValueError(f"lookup-table outputs must fit in {output_bit_size} bits")

        object.__setattr__(self, "values", frozen_values)
        object.__setattr__(self, "input_bit_size", input_bit_size)
        object.__setattr__(self, "output_bit_size", output_bit_size)

    @classmethod
    def identity(cls, input_bit_size: int, output_bit_size: int | None = None) -> "LookupTable":
        """Return the identity lookup for the requested widths.

        EXAMPLES::

            >>> from claasp_next.components import LookupTable
            >>> LookupTable.identity(2).values
            (0, 1, 2, 3)
        """

        input_bit_size = _positive_bit_size(input_bit_size, "input_bit_size")
        return cls(range(1 << input_bit_size), input_bit_size, output_bit_size)

    def is_bijective(self) -> bool:
        """Return whether this table is a bijection on equally sized spaces.

        EXAMPLES::

            >>> from claasp_next.components import LookupTable
            >>> LookupTable([0, 0], 1).is_bijective()
            False
        """

        return self.output_bit_size == self.input_bit_size and sorted(self.values) == list(
            range(1 << self.input_bit_size)
        )


__all__ = ["LookupTable"]
