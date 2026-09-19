"""One-component data-dependent rotation function."""

from claasp_next.components import VariableRotate as VariableRotateComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType

from ._base import positive


class VariableRotate(Primitive):
    """Rotate a word by an amount supplied as a second input.

    The default direction is right, so rotating ``10000001`` by two produces
    ``01100000`` and retains both set bits.

    >>> f"{VariableRotate().evaluate(0x81, 2):08b}"
    '01100000'

    ``amount_bit_size`` sets the width of the second input:

    >>> rotate = VariableRotate(bit_size=32, amount_bit_size=5, direction="left")
    >>> hex(rotate.evaluate(0x80000001, 1))
    '0x3'


    EXAMPLES::

        >>> primitive = VariableRotate()
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
            "variable_rotate",
            {
                "input": ValueType(Word(bit_size), (1,)),
                "amount": ValueType(Word(amount_bit_size), (1,)),
            },
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        self.set_output(
            self.add_component(
                VariableRotateComponent(
                    self.input("input"),
                    self.input("amount"),
                    direction,
                )
            )
        )


__all__ = ["VariableRotate"]
