"""Single-component modular-addition primitive implementation."""

from claasp_next.components import ModularAdd as ModularAddComponent
from claasp_next.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class ModularAdd(Primitive):
    """Add fixed-width words modulo a power of two.

    The default width is four bits, so ``11 + 7 = 18`` wraps modulo 16.

    >>> ModularAdd().evaluate(11, 7)
    2

    >>> three_way = ModularAdd(word_bit_size=8, number_of_inputs=3)
    >>> three_way.evaluate(200, 100, 10)
    54


    EXAMPLES::

        >>> primitive = ModularAdd()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "modadd",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(ModularAddComponent(operands))
        self.set_output(output)


__all__ = ["ModularAdd"]
