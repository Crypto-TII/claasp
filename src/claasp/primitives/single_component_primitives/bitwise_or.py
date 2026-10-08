"""Primitive consisting of one bitwise OR."""

from claasp.components import BitwiseOr as BitwiseOrComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class BitwiseOr(Primitive):
    """OR two or more fixed-width words, bit by bit.

    >>> f"{BitwiseOr().evaluate(0b1010, 0b0101):04b}"
    '1111'

    >>> three_way = BitwiseOr(word_bit_size=8, number_of_inputs=3)
    >>> hex(three_way.evaluate(0xF0, 0x0C, 0x03))
    '0xff'


    EXAMPLES::

        >>> primitive = BitwiseOr()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "or",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.inputs()
        output = self._builder.add_component(BitwiseOrComponent(operands))
        self._builder.set_output(output)


__all__ = ["BitwiseOr"]
