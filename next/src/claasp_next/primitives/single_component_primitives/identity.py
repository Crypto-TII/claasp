"""One-component identity permutation."""

from claasp_next.components import Identity as IdentityComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Identity(Primitive):
    """Return the input unchanged.

    >>> hex(Identity(16).evaluate(0xCAFE))
    '0xcafe'
    """

    def __init__(self, bit_size: int = 32) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "identity",
            {"input": ValueType(Bit(), (bit_size,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(IdentityComponent(self.input("input"))))


__all__ = ["Identity"]
