"""One-component bitwise-XOR primitive."""

from claasp_next.components import Xor as XorComponent
from ._base import NaryWordPrimitive


class Xor(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2) -> None:
        self._build("xor", XorComponent, word_bit_size, number_of_inputs)


__all__ = ["Xor"]
