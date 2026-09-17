"""One-component modular-subtraction primitive."""

from claasp_next.components import ModularSubtract
from ._base import NaryWordPrimitive


class Modsub(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modsub supports the canonical modulus 2^word_bit_size")
        self._build("modsub", ModularSubtract, word_bit_size, number_of_inputs)


__all__ = ["Modsub"]
