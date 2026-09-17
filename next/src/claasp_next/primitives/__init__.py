"""Primitive and permutation descriptions built on the typed graph."""

from claasp_next.primitives.block_ciphers import (
    AES128,
    AES,
    CustomAES,
    Present80,
    Present,
    Speck,
    Simon,
)
from claasp_next.primitives.block_functions import Trivium
from claasp_next.primitives.permutations.mimc import MiMC
from claasp_next.primitives.permutations.poseidon import Poseidon
from claasp_next.primitives.permutations.chacha import ChaCha
from claasp_next.primitives.permutations.salsa import Salsa
from claasp_next.primitives.toy_primitives import ToySpeck
from claasp_next.primitives._catalogue_exports import ALL_EXPORTS, load_export

__all__ = [
    "AES128",
    "AES",
    "CustomAES",
    "ChaCha",
    "MiMC",
    "Poseidon",
    "Present80",
    "Present",
    "Speck",
    "Simon",
    "Salsa",
    "Trivium",
    "ToySpeck",
]

__all__ = sorted(set(__all__) | set(ALL_EXPORTS))


def __getattr__(name: str):
    value = load_export(name)
    globals()[name] = value
    return value
