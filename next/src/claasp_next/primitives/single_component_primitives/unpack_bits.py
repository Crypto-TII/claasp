"""Primitive consisting of one bit-unpacking conversion."""

from claasp_next.components import UnpackBits as UnpackBitsComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class UnpackBits(Primitive):
    """Expand fixed-width words into MSB-first bits.

    >>> UnpackBits().evaluate(0xAB)
    171
    """

    def __init__(self, domain=None, word_count: int = 2) -> None:
        word_count = positive(word_count, "word_count")
        domain = Word(4) if domain is None else domain
        super().__init__(
            "unpack_bits",
            {"input": ValueType(domain, (word_count,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        output = self.add_component(UnpackBitsComponent(self.input("input")))
        self.set_output(output)


__all__ = ["UnpackBits"]
