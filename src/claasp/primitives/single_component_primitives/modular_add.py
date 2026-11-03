"""Single-component modular-addition primitive implementation."""

from claasp.components import ModularAdd as ModularAddComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import word_inputs


class ModularAdd(Primitive):
    """Add fixed-width words modulo a power of two.

    The default width is four bits, so ``11 + 7 = 18`` wraps modulo 16.

    >>> ModularAdd().evaluate(11, 7)
    2

    >>> three_way = ModularAdd(word_bit_size=8, number_of_inputs=3)
    >>> three_way.evaluate(200, 100, 10)
    54


    An explicit modulus also supports non-power-of-two experiments.

    >>> ModularAdd(word_bit_size=4, modulus=13).evaluate(11, 7)
    5

    EXAMPLES::

        >>> primitive = ModularAdd()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self, word_bit_size: int = 4, number_of_inputs: int = 2, *, modulus: int | None = None
    ) -> None:
        super().__init__(
            "modadd",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.graph.inputs()
        output = self._builder.add_component(ModularAddComponent(operands, modulus=modulus))
        self._builder.set_output(output)


__all__ = ["ModularAdd"]
