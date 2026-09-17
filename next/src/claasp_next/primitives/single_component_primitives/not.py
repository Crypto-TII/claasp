"""One-component bitwise-NOT permutation."""

from claasp_next.components import BitwiseNot
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Not(Primitive):
    def __init__(self, bit_size: int = 4) -> None:
        bit_size = positive(bit_size, "bit_size")
        value_type = ValueType(Word(bit_size), (1,))
        super().__init__("not", {"input": value_type}, kind=PrimitiveKind.PERMUTATION)
        self.add_round()
        self.set_output(self.add_component(BitwiseNot(self.input("input"))))


__all__ = ["Not"]
