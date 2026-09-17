"""Primitive consisting of one bit-unpacking conversion."""

from claasp_next.components import UnpackBits as UnpackBitsComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class UnpackBits(Primitive):
    """Expand fixed-width words into MSB-first bits.

    The default converts two four-bit words into eight individual bits. The
    evaluator encodes both typed forms as the same integer, while the graph's
    output type records the eight-bit structure.

    >>> unpacked = UnpackBits()
    >>> unpacked.components[0].output_type
    ValueType(domain=Bit(), shape=(8,))
    >>> hex(unpacked.evaluate(0xAB))
    '0xab'

    The input can instead be a vector of binary-field elements:

    >>> from claasp_next import BinaryExtensionField
    >>> field = BinaryExtensionField(4, 0b10011)
    >>> field_words = UnpackBits(domain=field, word_count=3)
    >>> hex(field_words.evaluate(0xABC))
    '0xabc'
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
