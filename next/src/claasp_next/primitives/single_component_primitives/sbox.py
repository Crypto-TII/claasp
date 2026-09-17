"""One-component lookup S-box primitive."""

from collections.abc import Sequence

from claasp_next.components import BitVectorSBox
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Sbox(Primitive):
    def __init__(self, bit_size: int = 4, lookup_table: Sequence[int] | None = None) -> None:
        bit_size = positive(bit_size, "bit_size")
        table = range(1 << bit_size) if lookup_table is None else lookup_table
        kind = (
            PrimitiveKind.PERMUTATION
            if sorted(table) == list(range(1 << bit_size))
            else PrimitiveKind.FUNCTION
        )
        super().__init__("sbox", {"input": ValueType(Bit(), (bit_size,))}, kind=kind)
        self.add_round()
        self.set_output(self.add_component(BitVectorSBox(self.input("input"), table)))


__all__ = ["Sbox"]
