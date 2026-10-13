"""Single-component constant-function primitive implementation."""

from claasp.components import Constant as ConstantComponent
from claasp.encoding import bits_from_int
from claasp.graph import Primitive, PrimitiveKind, UnitArrayType
from claasp.unit_types import Bit

from ._base import positive


class Constant(Primitive):
    """Return a fixed bit vector and take no inputs.

    >>> hex(Constant(8, 0x5A).evaluate())
    '0x5a'

    ``output_bit_size`` controls the exact width of the constant:

    >>> f"{Constant(output_bit_size=3, value=0b010).evaluate():03b}"
    '010'


    EXAMPLES::

        >>> primitive = Constant()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x2', 2)
    """

    def __init__(self, output_bit_size: int = 3, value: int = 0b010) -> None:
        output_bit_size = positive(output_bit_size, "output_bit_size")
        super().__init__("constant", {}, kind=PrimitiveKind.FUNCTION)
        self._builder.add_round()
        output = self._builder.add_component(
            ConstantComponent(
                UnitArrayType(Bit(), (output_bit_size,)),
                bits_from_int(value, output_bit_size),
            )
        )
        self._builder.set_output(output)


__all__ = ["Constant"]
