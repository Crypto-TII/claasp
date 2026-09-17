"""Primitive consisting of one domain-polymorphic addition."""

from claasp_next.components import Add as AddComponent
from claasp_next.graph import Primitive, PrimitiveKind
from ._base import algebraic_inputs


class Add(Primitive):
    """Add corresponding units in two or more inputs.

    The default domain is the prime field GF(17), so results are reduced
    modulo 17. Here ``5 + 14 = 19``, represented by ``2`` in GF(17).

    >>> from claasp_next import PrimeField
    >>> Add(PrimeField(17)).evaluate(5, 14)
    2
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
