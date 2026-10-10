"""Primitive consisting of one bitwise NOT."""

from claasp.components import BitwiseNot as BitwiseNotComponent
from claasp.domains import Word
from claasp.graph import ArrayType, Primitive, PrimitiveKind

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
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xf', 4)
    """

    def __init__(self, bit_size: int = 4) -> None:
        bit_size = positive(bit_size, "bit_size")
        array_type = ArrayType(Word(bit_size), (1,))
        super().__init__("not", {"input": array_type}, kind=PrimitiveKind.PERMUTATION)
        self._builder.add_round()
        self._builder.set_output(
            self._builder.add_component(BitwiseNotComponent(self.graph.input("input")))
        )


__all__ = ["BitwiseNot"]
