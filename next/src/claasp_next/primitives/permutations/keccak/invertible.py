"""Keccak realization with explicit invertible round operations."""

from claasp_next.primitives.permutations.keccak.sbox import KeccakSbox


class KeccakInvertible(KeccakSbox):
    """A forward Keccak graph whose round components are individually invertible."""

__all__ = ["KeccakInvertible"]
