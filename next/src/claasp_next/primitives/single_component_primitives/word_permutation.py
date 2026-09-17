"""One-component word permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class WordPermutation(Primitive):
    def __init__(
        self, word_size: int = 4, number_of_words: int = 4,
        permutation_description=None,
    ) -> None:
        word_size = positive(word_size, "word_size")
        number_of_words = positive(number_of_words, "number_of_words")
        description = (
            [1, 2, 3, 0]
            if permutation_description is None
            else permutation_description
        )
        super().__init__(
            "word_permutation",
            {"input": ValueType(Word(word_size), (number_of_words,))},
            kind=PrimitiveKind.PERMUTATION,
        )
        self.add_round()
        output = self.add_component(PermutationComponent.from_destinations(
            self.input("input"), description,
        ))
        self.set_output(output)


__all__ = ["WordPermutation"]
