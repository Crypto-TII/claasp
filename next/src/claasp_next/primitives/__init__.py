"""Primitive and permutation descriptions built on the typed graph."""

from claasp_next.primitives._catalogue_exports import ALL_EXPORTS, load_export
from claasp_next.primitives.block_ciphers import (
    AES,
    AES128,
    CustomAES,
    Present,
    Present80,
    Simon,
    Speck,
)
from claasp_next.primitives.block_functions import Trivium
from claasp_next.primitives.permutations.chacha import ChaCha
from claasp_next.primitives.permutations.mimc import MiMC
from claasp_next.primitives.permutations.poseidon import Poseidon
from claasp_next.primitives.permutations.salsa import Salsa
from claasp_next.primitives.toy_primitives import ToySpeck

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
