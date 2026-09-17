"""One-component modular-multiplication primitive."""

from claasp_next.components import ModularMultiply
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class Modmul(Primitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modmul supports the canonical modulus 2^word_bit_size")
        super().__init__(
            "modmul", word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(ModularMultiply(operands))
        self.set_output(output)


__all__ = ["Modmul"]
