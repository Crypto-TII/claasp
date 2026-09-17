"""One-component word permutation."""

from .permutation import Permutation


class WordPermutation(Permutation):
    def __init__(
        self, word_size: int = 4, number_of_words: int = 4,
        permutation_description=None,
    ) -> None:
        description = [1, 2, 3, 0] if permutation_description is None else permutation_description
        super().__init__(word_size * number_of_words, description, word_size)
        self._family_name = "word_permutation"


__all__ = ["WordPermutation"]
