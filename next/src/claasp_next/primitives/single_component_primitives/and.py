"""One-component bitwise-AND primitive."""

from claasp_next.components import BitwiseAnd
from ._base import NaryWordPrimitive


class And(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        self._build("and", BitwiseAnd, word_bit_size, number_of_inputs)


__all__ = ["And"]
