"""Primitive consisting of one bitwise NOT."""

from claasp_next.components import BitwiseNot as BitwiseNotComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class BitwiseNot(Primitive):
    """Invert every bit in a fixed-width word.

    >>> BitwiseNot().evaluate(0b1010)
    5
    """

    def __init__(self, bit_size: int = 4) -> None:
        bit_size = positive(bit_size, "bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        super().__init__("not", {"input": value_type}, kind=PrimitiveKind.PERMUTATION)
        self.add_round()
        self.set_output(self.add_component(BitwiseNotComponent(self.input("input"))))


__all__ = ["BitwiseNot"]
