"""One-component fixed-rotation permutation."""

from claasp_next.components import Rotate as RotateComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Rotate(Primitive):
    def __init__(self, bit_size: int = 8, rotation_amount: int = 1) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "rotate", {"input": ValueType(Word(bit_size), (1,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        direction = "right" if rotation_amount >= 0 else "left"
        self.set_output(self.add_component(RotateComponent(
            self.input("input"), abs(rotation_amount), direction
        )))


__all__ = ["Rotate"]
