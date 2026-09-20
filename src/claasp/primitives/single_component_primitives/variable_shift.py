"""One-component data-dependent shift function."""

from claasp.components import VariableShift as VariableShiftComponent
from claasp.domains import Word
from claasp.graph import Primitive, PrimitiveKind, ValueType

from ._base import positive


class VariableShift(Primitive):
    """Shift a word by an amount supplied as a second input.

    The default direction is right, so shifting ``10000001`` by two discards
    the low set bit and fills the two high positions with zeroes.

    >>> f"{VariableShift().evaluate(0x81, 2):08b}"
    '00100000'

    >>> shift = VariableShift(bit_size=32, amount_bit_size=5, direction="left")
    >>> hex(shift.evaluate(0x80000001, 1))
    '0x2'


    EXAMPLES::

        >>> primitive = VariableShift()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self,
        bit_size: int = 8,
        amount_bit_size: int = 3,
        direction: str = "right",
    ) -> None:
        bit_size = positive(bit_size, "bit_size")
        positive(amount_bit_size, "amount_bit_size")
        super().__init__(
            "variable_shift",
            {
                "input": ValueType(Word(bit_size), (1,)),
                "amount": ValueType(Word(amount_bit_size), (1,)),
            },
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(
            self.add_component(
                VariableShiftComponent(
                    self.input("input"),
                    self.input("amount"),
                    direction,
                )
            )
        )


__all__ = ["VariableShift"]
