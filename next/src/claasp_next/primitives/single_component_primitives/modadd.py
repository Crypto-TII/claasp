"""One-component modular-addition primitive."""

from claasp_next.components import ModularAdd
from ._base import NaryWordPrimitive


class Modadd(NaryWordPrimitive):
    def __init__(self, word_bit_size: int = 4, number_of_inputs: int = 2, modulus=None) -> None:
        if modulus not in (None, 1 << word_bit_size):
            raise ValueError("Modadd supports the canonical modulus 2^word_bit_size")
        self._build("modadd", ModularAdd, word_bit_size, number_of_inputs)


__all__ = ["Modadd"]
