"""Single-component fixed-rotation primitive implementation."""

from claasp_next.components import Rotate as RotateComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Rotate(Primitive):
    """Rotate a fixed-width word in the requested direction.

    Rotating the eight-bit word ``10000001`` left by two positions produces
    ``00000110``; bits shifted off the left re-enter on the right.

    >>> f"{Rotate(8, 2, 'left').evaluate(0x81):08b}"
    '00000110'

    >>> hex(Rotate(bit_size=32, amount=7, direction="right").evaluate(1))
    '0x2000000'


    EXAMPLES::

        >>> primitive = Rotate()
        >>> inputs = {name: 0 for name in primitive.input_ports}
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
            "rotate",
            {"input": ValueType(Word(bit_size), (1,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(
            self.add_component(RotateComponent(self.input("input"), amount, direction))
        )


__all__ = ["Rotate"]
