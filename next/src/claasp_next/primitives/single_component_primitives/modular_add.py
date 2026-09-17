"""One-component modular-addition primitive."""

from claasp_next.components import ModularAdd as ModularAddComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class ModularAdd(Primitive):
    """Add fixed-width words modulo a power of two.

    The default width is four bits, so ``11 + 7 = 18`` wraps modulo 16.

    >>> ModularAdd().evaluate(11, 7)
    2
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
