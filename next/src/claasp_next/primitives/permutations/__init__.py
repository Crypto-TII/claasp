"""Unkeyed cryptographic permutation graph implementations."""

from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export
from claasp_next.primitives.permutations.chacha import ChaCha as ChaCha
from claasp_next.primitives.permutations.mimc import MiMC as MiMC
from claasp_next.primitives.permutations.poseidon import Poseidon as Poseidon
from claasp_next.primitives.permutations.salsa import Salsa as Salsa

_PUBLIC = CATEGORY_EXPORTS["permutations"]
__all__ = sorted(_PUBLIC)


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
