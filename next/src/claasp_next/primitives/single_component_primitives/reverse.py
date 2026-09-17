"""One-component bit-reversal permutation."""

from .permutation import Permutation


class Reverse(Permutation):
    def __init__(self, bit_size: int = 8) -> None:
        super().__init__(bit_size, tuple(reversed(range(bit_size))))
        self._family_name = "reverse"


__all__ = ["Reverse"]
