"""One-component modular-subtraction primitive."""

from claasp_next.components import ModularSubtract
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class Modsub(Primitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        super().__init__(
            "modsub", word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(ModularSubtract(operands))
        self.set_output(output)


__all__ = ["Modsub"]
