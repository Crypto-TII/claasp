"""One-component modular-multiplication primitive."""

from claasp_next.components import ModularMultiply as ModularMultiplyComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class ModularMultiply(Primitive):
    """Multiply fixed-width words modulo a power of two.

    The default width is four bits. Here ``3 * 6 = 18`` wraps modulo 16.

    >>> ModularMultiply().evaluate(3, 6)
    2
    """

    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "modmul",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(ModularMultiplyComponent(operands))
        self.set_output(output)


__all__ = ["ModularMultiply"]
