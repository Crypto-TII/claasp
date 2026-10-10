"""Single-component fixed-shift primitive implementation."""

from claasp.components import Shift as ShiftComponent
from claasp.domains import Word
from claasp.graph import ArrayType, Primitive, PrimitiveKind

from ._base import positive


class Shift(Primitive):
    """Shift a fixed-width word, filling with zeroes.

    The default direction is right. Unlike rotation, the low bit discarded
    from ``10000001`` does not re-enter at the other end.

    >>> f"{Shift(8, 1).evaluate(0x81):08b}"
    '01000000'

    >>> hex(Shift(bit_size=32, amount=7, direction="left").evaluate(1))
    '0x80'


    EXAMPLES::

        >>> primitive = Shift()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
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
            {"input": ArrayType(Word(bit_size), (1,))},
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        self._builder.set_output(
            self._builder.add_component(
                ShiftComponent(self.graph.input("input"), amount, direction)
            )
        )


__all__ = ["Shift"]
