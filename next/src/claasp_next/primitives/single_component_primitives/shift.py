"""One-component fixed-shift function."""

from claasp_next.components import Shift as ShiftComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Shift(Primitive):
    """Shift a fixed-width word, filling with zeroes.

    >>> hex(Shift(8, 1).evaluate(0x81))
    '0x40'
    """

    def __init__(
        self,
        bit_size: int = 8,
        amount: int = 1,
        direction: str = "right",
    ) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "shift",
            {"input": ValueType(Word(bit_size), (1,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(
            self.add_component(ShiftComponent(self.input("input"), amount, direction))
        )


__all__ = ["Shift"]
