"""One-component identity permutation."""

from claasp_next.components import Identity as IdentityComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Identity(Primitive):
    def __init__(self, block_bit_size: int = 32) -> None:
        block_bit_size = positive(block_bit_size, "block_bit_size")
        super().__init__(
            "identity", {"input": ValueType(Bit(), (block_bit_size,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(IdentityComponent(self.input("input"))))


__all__ = ["Identity"]
