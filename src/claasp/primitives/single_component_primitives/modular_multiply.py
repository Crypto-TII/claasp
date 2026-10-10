"""Single-component modular-multiplication primitive implementation."""

from claasp.components import ModularMultiply as ModularMultiplyComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class ModularMultiply(Primitive):
    """Multiply fixed-width words modulo a power of two.

    The default width is four bits. Here ``3 * 6 = 18`` wraps modulo 16.

    >>> ModularMultiply().evaluate(3, 6)
    2

    >>> three_way = ModularMultiply(word_bit_size=8, number_of_inputs=3)
    >>> three_way.evaluate(2, 3, 5)
    30


    EXAMPLES::

        >>> primitive = ModularMultiply()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "modmul",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.graph.inputs()
        output = self._builder.add_component(ModularMultiplyComponent(operands))
        self._builder.set_output(output)


__all__ = ["ModularMultiply"]
