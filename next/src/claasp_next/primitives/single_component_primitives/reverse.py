"""One-component bit-reversal permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Reverse(Primitive):
    def __init__(self, bit_size: int = 8) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "reverse", {"input": ValueType(Bit(), (bit_size,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        output = self.add_component(PermutationComponent.reverse(self.input("input")))
        self.set_output(output)


__all__ = ["Reverse"]
