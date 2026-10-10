"""Primitive consisting of one unit-wise S-box."""

from collections.abc import Sequence

from claasp.components import LookupTable
from claasp.components import SBox as SBoxComponent
from claasp.domains import Word
from claasp.graph import ArrayType, Primitive, PrimitiveKind

from ._base import positive


class SBox(Primitive):
    """Apply one lookup table independently to every input unit.

    This example splits ``0001`` into two two-bit units, ``00`` and ``01``.
    The table maps them independently to ``11`` and ``10``, yielding ``1110``.

    >>> layer = SBox(lookup_table=[3, 2, 1, 0], domain=Word(2), unit_count=2)
    >>> result = layer.evaluate(0b0001)
    >>> f"{result:04b}"
    '1110'

    Omit the table for the identity lookup, or select another finite domain
    and number of units explicitly:

    >>> identity_layer = SBox(domain=Word(8), unit_count=2)
    >>> hex(identity_layer.evaluate(0x12AB))
    '0x12ab'


    EXAMPLES::

        >>> primitive = SBox()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self,
        lookup_table: Sequence[int] | None = None,
        domain=None,
        unit_count: int = 1,
    ) -> None:
        unit_count = positive(unit_count, "unit_count")
        domain = Word(4) if domain is None else domain
        table = (
            LookupTable.identity(domain.encoded_bit_size)
            if lookup_table is None
            else LookupTable(lookup_table, domain.encoded_bit_size)
        )
        kind = PrimitiveKind.PERMUTATION if table.is_bijective() else PrimitiveKind.FUNCTION
        super().__init__("sbox", {"input": ArrayType(domain, (unit_count,))}, kind=kind)
        self._builder.add_round()
        output = self._builder.add_component(SBoxComponent(self.graph.input("input"), table))
        self._builder.set_output(output)


__all__ = ["SBox"]
