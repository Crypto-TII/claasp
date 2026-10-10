"""Single-component identity-permutation primitive implementation."""

from claasp.components import Identity as IdentityComponent
from claasp.domains import Bit
from claasp.graph import ArrayType, Primitive, PrimitiveKind

from ._base import positive


class Identity(Primitive):
    """Return a fixed-width bit vector unchanged.

    >>> hex(Identity(16).evaluate(0xCAFE))
    '0xcafe'

    >>> hex(Identity(bit_size=128).evaluate(0x0123456789ABCDEF))
    '0x123456789abcdef'


    EXAMPLES::

        >>> primitive = Identity()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, bit_size: int = 32) -> None:
        bit_size = positive(bit_size, "bit_size")
        super().__init__(
            "identity",
            {"input": ArrayType(Bit(), (bit_size,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self._builder.add_round()
        self._builder.set_output(
            self._builder.add_component(IdentityComponent(self.graph.input("input")))
        )


__all__ = ["Identity"]
