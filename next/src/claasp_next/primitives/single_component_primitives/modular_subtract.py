"""Single-component modular-subtraction primitive implementation."""

from claasp_next.components import ModularSubtract as ModularSubtractComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class ModularSubtract(Primitive):
    """Subtract fixed-width words modulo a power of two.

    The default width is four bits, so ``3 - 5 = -2`` wraps modulo 16.

    >>> ModularSubtract().evaluate(3, 5)
    14

    >>> three_way = ModularSubtract(word_bit_size=8, number_of_inputs=3)
    >>> three_way.evaluate(20, 7, 2)
    11


    EXAMPLES::

        >>> primitive = ModularSubtract()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "modsub",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(ModularSubtractComponent(operands))
        self.set_output(output)


__all__ = ["ModularSubtract"]
