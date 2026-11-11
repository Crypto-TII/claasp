"""Single-component modular-multiplication primitive implementation."""

from claasp._catalogue_metadata import _entry
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


    An explicit modulus also supports non-power-of-two experiments.

    >>> ModularMultiply(word_bit_size=4, modulus=13).evaluate(11, 7)
    12

    EXAMPLES::

        >>> primitive = ModularMultiply()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self, word_bit_size: int = 4, number_of_inputs: int = 2, *, modulus: int | None = None
    ) -> None:
        super().__init__(
            "modmul",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.graph.inputs()
        output = self._builder.add_component(ModularMultiplyComponent(operands, modulus=modulus))
        self._builder.set_output(output)


__all__ = ["ModularMultiply"]


__catalogue__ = (_entry("primitive", ModularMultiply),)
