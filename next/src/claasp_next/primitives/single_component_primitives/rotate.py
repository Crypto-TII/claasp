"""One-component fixed-rotation permutation."""

from claasp_next.components import Rotate as RotateComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Rotate(Primitive):
    def __init__(
        self, bit_size: int = 8, amount: int = 1, direction: str = "right",
    ) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "rotate", {"input": ValueType(Word(bit_size), (1,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(RotateComponent(
            self.input("input"), amount, direction
        )))


__all__ = ["Rotate"]
