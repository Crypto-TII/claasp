"""Primitive consisting of one unit_type-polymorphic power map."""

from math import gcd

from claasp.components import Power as PowerComponent
from claasp.graph import Primitive, PrimitiveKind, UnitArrayType
from claasp.unit_types import BinaryExtensionField, Bit, PrimeField

from ._base import positive


class Power(Primitive):
    """Raise every input unit to a fixed exponent.

    The default cubes one GF(2) element. Choose a different exponent, unit_type,
    or vector length through the constructor:

    >>> Power().evaluate(1)
    1
    >>> cubic = Power(exponent=3, unit_type=PrimeField(17), unit_count=1)
    >>> cubic.evaluate(3)
    10


    EXAMPLES::

        >>> primitive = Power()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, exponent: int = 3, unit_type=None, unit_count: int = 1) -> None:
        unit_type = Bit() if unit_type is None else unit_type
        exponent = positive(exponent, "exponent")
        unit_count = positive(unit_count, "unit_count")
        if isinstance(unit_type, Bit):
            order = 2
        elif isinstance(unit_type, PrimeField):
            order = unit_type.modulus
        elif isinstance(unit_type, BinaryExtensionField):
            order = 1 << unit_type.degree
        else:
            raise TypeError("power requires Bit, PrimeField, or BinaryExtensionField")
        kind = (
            PrimitiveKind.PERMUTATION if gcd(exponent, order - 1) == 1 else PrimitiveKind.FUNCTION
        )
        super().__init__("power", {"input": UnitArrayType(unit_type, (unit_count,))}, kind=kind)
        self._builder.add_round()
        output = self._builder.add_component(PowerComponent(self.graph.input("input"), exponent))
        self._builder.set_output(output)


__all__ = ["Power"]
