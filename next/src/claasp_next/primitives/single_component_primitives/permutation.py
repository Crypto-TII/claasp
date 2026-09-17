"""One-component logical-unit permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class Permutation(Primitive):
    """Apply ``output[i] = input[mapping[i]]`` to bits or words.

    This example swaps two four-bit words, turning ``AB`` into ``BA``.

    >>> hex(Permutation([1, 0], 4).evaluate(0xAB))
    '0xba'

    Omit ``word_size`` for a bit permutation, or set it to permute wider
    logical units:

    >>> reverse_bits = Permutation(mapping=[3, 2, 1, 0])
    >>> reverse_bytes = Permutation(mapping=[3, 2, 1, 0], word_size=8)
    >>> (reverse_bits.components[0].output_type, reverse_bytes.components[0].output_type)
    (ValueType(domain=Bit(), shape=(4,)), ValueType(domain=Word(width=8), shape=(4,)))
    """

    def __init__(self, mapping=None, word_size: int = 1) -> None:
        word_size = positive(word_size, "word_size")
        mapping = list(reversed(range(8))) if mapping is None else list(mapping)
        count = len(mapping)
        domain = Bit() if word_size == 1 else Word(word_size)
        super().__init__(
            "permutation",
            {"input": ValueType(domain, (count,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(
            self.add_component(
                PermutationComponent(
                    self.input("input"),
                    mapping,
                )
            )
        )


__all__ = ["Permutation"]
