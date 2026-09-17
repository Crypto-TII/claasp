"""One-component logical-unit permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import inverse_mapping, positive


class Permutation(Primitive):
    def __init__(self, bit_size: int = 8, permutation_description=None, word_size: int = 1) -> None:
        bit_size = positive(bit_size, "bit_size")
        word_size = positive(word_size, "word_size")
        if bit_size % word_size:
            raise ValueError("bit_size must be divisible by word_size")
        count = bit_size // word_size
        description = (
            tuple(reversed(range(count)))
            if permutation_description is None
            else tuple(permutation_description)
        )
        domain = Bit() if word_size == 1 else Word(word_size)
        super().__init__(
            "permutation", {"input": ValueType(domain, (count,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        self.set_output(self.add_component(PermutationComponent(
            self.input("input"), inverse_mapping(description)
        )))


__all__ = ["Permutation"]
