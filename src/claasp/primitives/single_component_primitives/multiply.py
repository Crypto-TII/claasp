"""Primitive consisting of one domain-polymorphic multiplication."""

from claasp.components import Multiply as MultiplyComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import algebraic_inputs


class Multiply(Primitive):
    """Multiply corresponding units in two or more inputs.

    The default domain is GF(2), where multiplication is AND.

    >>> Multiply().evaluate(1, 0)
    0

    Select another domain explicitly when needed:

    >>> from claasp import PrimeField
    >>> Multiply(domain=PrimeField(17)).evaluate(5, 7)
    1

    ``unit_count`` and ``number_of_inputs`` build component-wise vector
    multiplication with the requested arity:

    >>> vector_multiply = Multiply(unit_count=4, number_of_inputs=3)
    >>> f"{vector_multiply.evaluate(0b1111, 0b1100, 0b1010):04b}"
    '1000'


    EXAMPLES::

        >>> primitive = Multiply()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, domain=None, unit_count: int = 1, number_of_inputs: int = 2) -> None:
        super().__init__(
            "multiply",
            algebraic_inputs(domain, unit_count, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        output = self.add_component(MultiplyComponent(self.inputs()))
        self.set_output(output)


__all__ = ["Multiply"]
