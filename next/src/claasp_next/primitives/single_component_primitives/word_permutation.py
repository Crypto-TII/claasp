"""One-component word permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class WordPermutation(Primitive):
    """Apply ``output[i] = input[mapping[i]]`` to fixed-width words."""

    def __init__(self, word_size: int = 4, mapping=None) -> None:
        word_size = positive(word_size, "word_size")
        mapping = [3, 0, 1, 2] if mapping is None else list(mapping)
        super().__init__(
            "word_permutation",
            {"input": ValueType(Word(word_size), (len(mapping),))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        output = self.add_component(PermutationComponent(
            self.input("input"), mapping,
        ))
        self.set_output(output)


__all__ = ["WordPermutation"]
