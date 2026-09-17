"""One-component modular-multiplication primitive."""

from claasp_next.components import ModularMultiply
from ._base import NaryWordPrimitive


class Modmul(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modmul supports the canonical modulus 2^word_bit_size")
        self._build("modmul", ModularMultiply, word_bit_size, number_of_inputs)


__all__ = ["Modmul"]
