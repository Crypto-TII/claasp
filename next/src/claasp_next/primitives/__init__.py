"""Primitive and permutation descriptions built on the typed graph."""

from claasp_next.primitives.block_ciphers import (
    AES128,
    AES,
    Present80,
    Present,
    Speck,
    Simon,
)
from claasp_next.primitives.permutations.mimc import MiMC
from claasp_next.primitives.permutations.poseidon import Poseidon
from claasp_next.primitives.permutations.chacha import ChaCha
from claasp_next.primitives.permutations.salsa import Salsa

__all__ = [
    "AES128",
    "AES",
    "ChaCha",
    "MiMC",
    "Poseidon",
    "Present80",
    "Present",
    "Speck",
    "Simon",
    "Salsa",
]
