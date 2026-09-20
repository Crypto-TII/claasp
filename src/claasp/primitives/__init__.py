"""Primitive and permutation descriptions built on the typed graph."""

from claasp.primitives._catalogue_exports import ALL_EXPORTS, load_export
from claasp.primitives.block_ciphers import (
    AES,
    AES128,
    CustomAES,
    Present,
    Present80,
    Simon,
    Speck,
)
from claasp.primitives.block_functions import Trivium
from claasp.primitives.permutations.chacha import ChaCha
from claasp.primitives.permutations.mimc import MiMC
from claasp.primitives.permutations.poseidon import Poseidon
from claasp.primitives.permutations.salsa import Salsa
from claasp.primitives.toy_primitives import ToySpeck

__all__ = [
    "AES",
    "AES128",
    "ChaCha",
    "CustomAES",
    "MiMC",
    "Poseidon",
    "Present",
    "Present80",
    "Salsa",
    "Simon",
    "Speck",
    "ToySpeck",
    "Trivium",
]

__all__ = sorted(set(__all__) | set(ALL_EXPORTS))


def __getattr__(name: str):
    value = load_export(name)
    globals()[name] = value
    return value
