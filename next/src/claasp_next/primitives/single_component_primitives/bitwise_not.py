"""Primitive consisting of one bitwise NOT."""

from claasp_next.components import BitwiseNot as BitwiseNotComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType

from ._base import positive


class BitwiseNot(Primitive):
    """Invert every bit in a fixed-width word.

    The default word width is four bits, so only those four bits are inverted.

    >>> f"{BitwiseNot().evaluate(0b1010):04b}"
    '0101'

    >>> hex(BitwiseNot(bit_size=32).evaluate(0))
    '0xffffffff'


    EXAMPLES::

        >>> primitive = BitwiseNot()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xf', 4)
    """

    def __init__(self, bit_size: int = 4) -> None:
        bit_size = positive(bit_size, "bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        super().__init__("not", {"input": value_type}, kind=PrimitiveKind.PERMUTATION)
        self.add_round()
        self.set_output(self.add_component(BitwiseNotComponent(self.input("input"))))


__all__ = ["BitwiseNot"]
