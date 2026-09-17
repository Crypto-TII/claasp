"""One-component row/word rotation permutation."""

from claasp_next.components import Permutation as PermutationComponent
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class ShiftRows(Primitive):
    def __init__(self, rotation_amount: int = 1, word_bit_size: int = 8, number_of_words: int = 4) -> None:
        positive(word_bit_size, "word_bit_size")
        positive(number_of_words, "number_of_words")
        value_type = ValueType(Word(word_bit_size), (number_of_words,))
        super().__init__("shift_rows", {"input": value_type}, kind=PrimitiveKind.PERMUTATION)
        self.add_round()
        mapping = tuple((index - rotation_amount) % number_of_words for index in range(number_of_words))
        self.set_output(self.add_component(PermutationComponent(self.input("input"), mapping)))


__all__ = ["ShiftRows"]
