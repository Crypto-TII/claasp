"""Primitive consisting of one explicit structural concatenation."""

from claasp_next.components import Concatenate as ConcatenateComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Concatenate(Primitive):
    """Join equal-width inputs into one MSB-first bit vector.

    The default joins two two-bit inputs: ``10`` followed by ``01`` is
    the four-bit vector ``1001``.

    >>> f"{Concatenate().evaluate(0b10, 0b01):04b}"
    '1001'

    >>> three_bytes = Concatenate(input_bit_size=8, number_of_inputs=3)
    >>> three_bytes.components[0].output_type
    ValueType(domain=Bit(), shape=(24,))
    """

    def __init__(self, input_bit_size: int = 2, number_of_inputs: int = 2) -> None:
        input_bit_size = positive(input_bit_size, "input_bit_size")
        number_of_inputs = positive(number_of_inputs, "number_of_inputs")
        value_type = ValueType(Bit(), (input_bit_size,))
        inputs = {f"input_{index}": value_type for index in range(number_of_inputs)}
        super().__init__("concatenate", inputs, kind=PrimitiveKind.FUNCTION)
        self.add_round()
        output = self.add_component(ConcatenateComponent(self.inputs()))
        self.set_output(output)


__all__ = ["Concatenate"]
