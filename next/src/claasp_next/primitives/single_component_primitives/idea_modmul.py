"""One-component IDEA zero-encoded multiplication primitive."""

from claasp_next.components import IDEAMultiply
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class IdeaModmul(Primitive):
    def __init__(self, word_bit_size: int = 16, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, (1 << word_bit_size) + 1):
            raise ValueError("IDEA multiplication modulus must be 2^word_bit_size + 1")
        super().__init__(
            "idea_modmul", word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = tuple(self.input(name) for name in self.inputs)
        output = self.add_component(IDEAMultiply(operands))
        self.set_output(output)


__all__ = ["IdeaModmul"]
