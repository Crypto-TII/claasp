"""Primitive consisting of one domain-polymorphic power map."""

from math import gcd

from claasp_next.components import Power as PowerComponent
from claasp_next.domains import BinaryExtensionField, Bit, PrimeField
from claasp_next.graph import Primitive, PrimitiveKind, ValueType

from ._base import positive


class Power(Primitive):
    """Raise every input unit to a fixed exponent.

    The default cubes one GF(2) element. Choose a different exponent, domain,
    or vector length through the constructor:

    >>> Power().evaluate(1)
    1
    >>> cubic = Power(exponent=3, domain=PrimeField(17), unit_count=1)
    >>> cubic.evaluate(3)
    10


    EXAMPLES::

        >>> primitive = Power()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, exponent: int = 3, domain=None, unit_count: int = 1) -> None:
        domain = Bit() if domain is None else domain
        exponent = positive(exponent, "exponent")
        unit_count = positive(unit_count, "unit_count")
        if isinstance(domain, Bit):
            order = 2
        elif isinstance(domain, PrimeField):
            order = domain.modulus
        elif isinstance(domain, BinaryExtensionField):
            order = 1 << domain.degree
        else:
            raise TypeError("power requires Bit, PrimeField, or BinaryExtensionField")
        kind = (
            PrimitiveKind.PERMUTATION if gcd(exponent, order - 1) == 1 else PrimitiveKind.FUNCTION
        )
        super().__init__("power", {"input": ValueType(domain, (unit_count,))}, kind=kind)
        self.add_round()
        output = self.add_component(PowerComponent(self.input("input"), exponent))
        self.set_output(output)


__all__ = ["Power"]
