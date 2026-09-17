"""One-component fixed-shift function."""

from claasp_next.components import Shift as ShiftComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Shift(Primitive):
    def __init__(self, bit_size: int = 8, shift_amount: int = 1) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "shift", {"input": ValueType(Word(bit_size), (1,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        direction = "right" if shift_amount >= 0 else "left"
        self.set_output(self.add_component(ShiftComponent(
            self.input("input"), abs(shift_amount), direction
        )))


__all__ = ["Shift"]
