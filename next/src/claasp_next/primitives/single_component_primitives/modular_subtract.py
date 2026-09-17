"""One-component modular-subtraction primitive."""

from claasp_next.components import ModularSubtract as ModularSubtractComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class ModularSubtract(Primitive):
    """Subtract fixed-width words modulo a power of two.

    >>> ModularSubtract().evaluate(3, 5)
    14
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
