"""One-component bitwise-OR primitive."""

from claasp_next.components import BitwiseOr
from ._base import NaryWordPrimitive


class Or(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        self._build("or", BitwiseOr, word_bit_size, number_of_inputs)


__all__ = ["Or"]
