"""Primitive consisting of one domain-polymorphic multiplication."""

from claasp_next.components import Multiply as MultiplyComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import algebraic_inputs


class Multiply(Primitive):
    """Multiply corresponding units in two or more inputs.

    The default domain is the prime field GF(17), so ``5 * 7 = 35`` is
    represented by ``1``.

    >>> from claasp_next import PrimeField
    >>> Multiply(PrimeField(17)).evaluate(5, 7)
    1
    """

    def __init__(
        self, domain=None, unit_count: int = 1, number_of_inputs: int = 2
    ) -> None:
        super().__init__(
            "multiply",
            algebraic_inputs(domain, unit_count, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self.add_round()
        output = self.add_component(MultiplyComponent(self.inputs()))
        self.set_output(output)


__all__ = ["Multiply"]
