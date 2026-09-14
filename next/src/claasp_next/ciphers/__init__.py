"""Cipher and permutation descriptions built on the typed graph."""

from claasp_next.ciphers.block_ciphers import (
    AES128BlockCipher,
    AESBlockCipher,
    Present80BlockCipher,
    PresentBlockCipher,
    SpeckBlockCipher,
    SimonBlockCipher,
)
from claasp_next.ciphers.block_functions import Trivium
from claasp_next.ciphers.permutations.mimc import MiMCPermutation
from claasp_next.ciphers.permutations.poseidon import PoseidonPermutation
from claasp_next.ciphers.permutations.chacha import ChaCha
from claasp_next.ciphers.permutations.salsa import Salsa

__all__ = [
    "AES128BlockCipher",
    "AESBlockCipher",
    "ChaCha",
    "MiMCPermutation",
    "PoseidonPermutation",
    "Present80BlockCipher",
    "PresentBlockCipher",
    "SpeckBlockCipher",
    "SimonBlockCipher",
    "Salsa",
    "Trivium",
]
