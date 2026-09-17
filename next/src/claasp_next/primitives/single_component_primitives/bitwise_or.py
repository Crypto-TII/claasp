"""Primitive consisting of one bitwise OR."""

from claasp_next.components import BitwiseOr as BitwiseOrComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class BitwiseOr(Primitive):
    """OR two or more fixed-width words, bit by bit.

    >>> f"{BitwiseOr().evaluate(0b1010, 0b0101):04b}"
    '1111'
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "or",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(BitwiseOrComponent(operands))
        self.set_output(output)


__all__ = ["BitwiseOr"]
