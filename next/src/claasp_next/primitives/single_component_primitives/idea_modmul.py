"""One-component IDEA zero-encoded multiplication primitive."""

from claasp_next.components import IDEAMultiply
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class IdeaModmul(Primitive):
    def __init__(self, word_bit_size: int = 16, number_of_inputs: int = 2) -> None:
        super().__init__(
            "idea_modmul", word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = self.inputs()
        output = self.add_component(IDEAMultiply(operands))
        self.set_output(output)


__all__ = ["IdeaModmul"]
