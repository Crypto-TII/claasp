"""Primitive consisting of one bit-packing conversion."""

from claasp_next.components import PackBits as PackBitsComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class PackBits(Primitive):
    """Pack MSB-first bits into fixed-width words.

    The default converts eight individual bits into two four-bit words. The
    evaluator encodes both typed forms as the same integer, while the graph's
    output type records the two-word structure.

    >>> packed = PackBits()
    >>> packed.components[0].output_type
    ValueType(domain=Word(width=4), shape=(2,))
    >>> hex(packed.evaluate(0xAB))
    '0xab'
    """

    def __init__(
        self, bit_count: int = 8, word_width: int = 4, output_domain=None
    ) -> None:
        bit_count = positive(bit_count, "bit_count")
        word_width = positive(word_width, "word_width")
        super().__init__(
            "pack_bits",
            {"input": ValueType(Bit(), (bit_count,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        output = self.add_component(
            PackBitsComponent(
                self.input("input"), word_width, output_domain=output_domain
            )
        )
        self.set_output(output)


__all__ = ["PackBits"]
