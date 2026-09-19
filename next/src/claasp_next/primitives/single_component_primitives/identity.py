"""Single-component identity-permutation primitive implementation."""

from claasp_next.components import Identity as IdentityComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType

from ._base import positive


class Identity(Primitive):
    """Return a fixed-width bit vector unchanged.

    >>> hex(Identity(16).evaluate(0xCAFE))
    '0xcafe'

    >>> hex(Identity(bit_size=128).evaluate(0x0123456789ABCDEF))
    '0x123456789abcdef'


    EXAMPLES::

        >>> primitive = Identity()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
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
