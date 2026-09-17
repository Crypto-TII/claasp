"""One-component fixed-shift function."""

from claasp_next.components import Shift as ShiftComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Shift(Primitive):
    """Shift a fixed-width word, filling with zeroes.

    The default direction is right. Unlike rotation, the low bit discarded
    from ``10000001`` does not re-enter at the other end.

    >>> f"{Shift(8, 1).evaluate(0x81):08b}"
    '01000000'

    >>> hex(Shift(bit_size=32, amount=7, direction="left").evaluate(1))
    '0x80'
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
