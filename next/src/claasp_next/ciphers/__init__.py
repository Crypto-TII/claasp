"""Cipher and permutation descriptions built on the typed graph."""

from claasp_next.ciphers.permutations.mimc import MiMCPermutation
from claasp_next.ciphers.permutations.poseidon import PoseidonPermutation

__all__ = ["MiMCPermutation", "PoseidonPermutation"]
