"""Primitive consisting of one domain-polymorphic addition."""

from claasp_next.components import Add as AddComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import algebraic_inputs


class Add(Primitive):
    """Add corresponding units in two or more inputs.

    The default domain is GF(2), where addition is XOR.

    >>> Add().evaluate(1, 1)
    0

    Select another domain explicitly when needed:

    >>> from claasp_next import PrimeField
    >>> Add(domain=PrimeField(17)).evaluate(5, 14)
    2

    ``unit_count`` applies addition component-wise to vectors, while
    ``number_of_inputs`` controls their arity:

    >>> vector_add = Add(unit_count=4, number_of_inputs=3)
    >>> f"{vector_add.evaluate(0b1010, 0b1100, 0b0111):04b}"
    '0001'
    """

    def __init__(
        self, domain=None, unit_count: int = 1, number_of_inputs: int = 2
    ) -> None:
        super().__init__(
            "add",
            algebraic_inputs(domain, unit_count, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        output = self.add_component(AddComponent(self.inputs()))
        self.set_output(output)


__all__ = ["Add"]
