"""Single-component bitwise-XOR primitive implementation."""

from claasp.components import Xor as XorComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class Xor(Primitive):
    """XOR two or more fixed-width words, bit by bit.

    >>> f"{Xor().evaluate(0b1010, 0b1100):04b}"
    '0110'

    >>> three_way = Xor(word_bit_size=8, number_of_inputs=3)
    >>> hex(three_way.evaluate(0xF0, 0xCC, 0xAA))
    '0x96'


    EXAMPLES::

        >>> primitive = Xor()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "xor",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.inputs()
        output = self._builder.add_component(XorComponent(operands))
        self._builder.set_output(output)


__all__ = ["Xor"]
