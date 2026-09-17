"""One-component bitwise-XOR primitive."""

from claasp_next.components import Xor as XorComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class Xor(Primitive):
    """XOR two or more fixed-width words, bit by bit.

    >>> f"{Xor().evaluate(0b1010, 0b1100):04b}"
    '0110'

    >>> three_way = Xor(word_bit_size=8, number_of_inputs=3)
    >>> len(three_way.inputs())
    3
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "xor",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(XorComponent(operands))
        self.set_output(output)


__all__ = ["Xor"]
