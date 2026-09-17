"""Primitive consisting of one unit-wise S-box."""

from collections.abc import Sequence

from claasp_next.components import SBox as SBoxComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class SBox(Primitive):
    """Apply one lookup table independently to every input unit.

    This example splits ``0001`` into two two-bit units, ``00`` and ``01``.
    The table maps them independently to ``11`` and ``10``, yielding ``1110``.

    >>> result = SBox([3, 2, 1, 0], Word(2), unit_count=2).evaluate(0b0001)
    >>> f"{result:04b}"
    '1110'
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
            list(range(1 << domain.encoded_bit_size))
            if lookup_table is None
            else list(lookup_table)
        )
        bijective = sorted(table) == list(range(1 << domain.encoded_bit_size))
        kind = PrimitiveKind.PERMUTATION if bijective else PrimitiveKind.FUNCTION
        super().__init__("sbox", {"input": ValueType(domain, (unit_count,))}, kind=kind)
        self.add_round()
        output = self.add_component(SBoxComponent(self.input("input"), table))
        self.set_output(output)


__all__ = ["SBox"]
