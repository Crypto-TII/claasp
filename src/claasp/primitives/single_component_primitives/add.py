"""Primitive consisting of one domain-polymorphic addition."""

from claasp.components import Add as AddComponent
from claasp.graph import Primitive, PrimitiveKind

from ._base import algebraic_inputs


class Add(Primitive):
    """Add corresponding units in two or more inputs.

    The default domain is GF(2), where addition is XOR.

    >>> Add().evaluate(1, 1)
    0

    Select another domain explicitly when needed:

    >>> from claasp import PrimeField
    >>> Add(domain=PrimeField(17)).evaluate(5, 14)
    2

    ``unit_count`` applies addition component-wise to vectors, while
    ``number_of_inputs`` controls their arity:

    >>> vector_add = Add(unit_count=4, number_of_inputs=3)
    >>> f"{vector_add.evaluate(0b1010, 0b1100, 0b0111):04b}"
    '0001'


    EXAMPLES::

        >>> primitive = Add()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, domain=None, unit_count: int = 1, number_of_inputs: int = 2) -> None:
        super().__init__(
            "add",
            algebraic_inputs(domain, unit_count, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        output = self._builder.add_component(AddComponent(self.inputs()))
        self._builder.set_output(output)


__all__ = ["Add"]
