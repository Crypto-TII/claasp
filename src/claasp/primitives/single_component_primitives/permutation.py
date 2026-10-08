"""Single-component logical-unit permutation primitive implementation."""

from claasp.components import Permutation as PermutationComponent
from claasp.domains import Bit, Word
from claasp.graph import Primitive, PrimitiveKind, ValueType

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
    >>> f"{reverse_bits.evaluate(0b1101):04b}"
    '1011'
    >>> hex(reverse_bytes.evaluate(0x01020304))
    '0x4030201'


    EXAMPLES::

        >>> primitive = Permutation()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
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
        self._builder.add_round()
        self._builder.set_output(
            self._builder.add_component(
                PermutationComponent(
                    self.input("input"),
                    mapping,
                )
            )
        )


__all__ = ["Permutation"]
