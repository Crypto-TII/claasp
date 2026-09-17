"""One-component constant function."""

from claasp_next.components import Constant as ConstantComponent
from claasp_next.domains import Bit
from claasp_next.encoding import bits_from_int
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Constant(Primitive):
    """Return a fixed bit vector and take no inputs.

    >>> hex(Constant(8, 0x5A).evaluate())
    '0x5a'

    ``output_bit_size`` controls the exact width of the constant:

    >>> f"{Constant(output_bit_size=3, value=0b010).evaluate():03b}"
    '010'
    """

    def __init__(self, output_bit_size: int = 3, value: int = 0b010) -> None:
        output_bit_size = positive(output_bit_size, "output_bit_size")
        super().__init__("constant", {}, kind=PrimitiveKind.FUNCTION)
        self.add_round()
        output = self.add_component(
            ConstantComponent(
                ValueType(Bit(), (output_bit_size,)),
                bits_from_int(value, output_bit_size),
            )
        )
        self.set_output(output)


__all__ = ["Constant"]
