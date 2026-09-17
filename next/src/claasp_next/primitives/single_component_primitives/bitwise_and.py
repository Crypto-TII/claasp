"""Primitive consisting of one bitwise AND."""

from claasp_next.components import BitwiseAnd as BitwiseAndComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class BitwiseAnd(Primitive):
    """AND two or more fixed-width words, bit by bit.

    >>> f"{BitwiseAnd().evaluate(0b1010, 0b1100):04b}"
    '1000'

    Request wider words and more operands through the constructor:

    >>> three_way = BitwiseAnd(word_bit_size=8, number_of_inputs=3)
    >>> len(three_way.inputs())
    3
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "and",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(BitwiseAndComponent(operands))
        self.set_output(output)


__all__ = ["BitwiseAnd"]
