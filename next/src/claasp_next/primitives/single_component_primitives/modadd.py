"""One-component modular-addition primitive."""

from claasp_next.components import ModularAdd
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import word_inputs


class Modadd(Primitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modadd supports the canonical modulus 2^word_bit_size")
        super().__init__(
            "modadd", word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        operands = tuple(self.input(name) for name in self.inputs)
        output = self.add_component(ModularAdd(operands))
        self.set_output(output)


__all__ = ["Modadd"]
