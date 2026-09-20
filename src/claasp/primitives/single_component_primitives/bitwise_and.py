"""Primitive consisting of one bitwise AND."""

from claasp.components import BitwiseAnd as BitwiseAndComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class BitwiseAnd(Primitive):
    """AND two or more fixed-width words, bit by bit.

    >>> f"{BitwiseAnd().evaluate(0b1010, 0b1100):04b}"
    '1000'

    Request wider words and more operands through the constructor:

    >>> three_way = BitwiseAnd(word_bit_size=8, number_of_inputs=3)
    >>> hex(three_way.evaluate(0xF0, 0xCC, 0xAA))
    '0x80'


    EXAMPLES::

        >>> primitive = BitwiseAnd()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
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
