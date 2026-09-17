"""One-component IDEA zero-encoded multiplication primitive."""

from claasp_next.components import IDEAMultiply
from ._base import NaryWordPrimitive


class IdeaModmul(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 16, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, (1 << word_bit_size) + 1):
            raise ValueError("IDEA multiplication modulus must be 2^word_bit_size + 1")
        self._build("idea_modmul", IDEAMultiply, word_bit_size, number_of_inputs)


__all__ = ["IdeaModmul"]
