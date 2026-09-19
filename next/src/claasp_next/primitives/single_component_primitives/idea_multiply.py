"""One-component IDEA zero-encoded multiplication primitive."""

from claasp_next.components import IDEAMultiply as IDEAMultiplyComponent
from claasp_next.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class IDEAMultiply(Primitive):
    """Multiply words using IDEA's zero encoding.

    For four-bit words, encoded zero denotes 16; multiplication is modulo
    17, and a result of 16 is encoded back as zero. Thus ``0 * 2`` means
    ``16 * 2 mod 17``, which is 15.

    >>> IDEAMultiply(4).evaluate(0, 2)
    15

    >>> three_way = IDEAMultiply(word_bit_size=16, number_of_inputs=3)
    >>> three_way.evaluate(2, 3, 4)
    24


    EXAMPLES::

        >>> primitive = IDEAMultiply()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x1', 1)
    """

    def __init__(self, word_bit_size: int = 16, number_of_inputs: int = 2) -> None:
        super().__init__(
            "idea_modmul",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(IDEAMultiplyComponent(operands))
        self.set_output(output)


__all__ = ["IDEAMultiply"]
