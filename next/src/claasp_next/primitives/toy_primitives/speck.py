"""Nonstandard Speck8/16 fixture, distinct from the official Speck catalogue."""

from claasp_next.primitives.block_ciphers.speck import Speck


class ToySpeck(Speck):
    """Four-bit words and the legacy toy's rotations (8 mod 4, 3).

    This regression primitive is not an official Speck configuration.
    """

    def __init__(self, number_of_rounds=4):
        if (not isinstance(number_of_rounds, int) or isinstance(number_of_rounds, bool)
                or not 1 <= number_of_rounds <= 4):
            raise ValueError("ToySpeck requires between one and four rounds")
        self._build_word_graph(4, 4, number_of_rounds, 0, 3, "toy_speck")
