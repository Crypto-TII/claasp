"""Keccak realization with explicit invertible round operations."""

from claasp.primitives.permutations.keccak.sbox import KeccakSbox


class KeccakInvertible(KeccakSbox):
    """A forward Keccak graph whose round components are individually invertible.

    EXAMPLES::

        >>> primitive = KeccakInvertible()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xf1258f7940e1dde7', 1600)
    """


__all__ = ["KeccakInvertible"]
