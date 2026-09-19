"""Unkeyed cryptographic permutation graph implementations."""

from claasp_next.primitives.permutations.chacha import ChaCha
from claasp_next.primitives.permutations.mimc import MiMC
from claasp_next.primitives.permutations.poseidon import Poseidon
from claasp_next.primitives.permutations.salsa import Salsa
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

_PUBLIC = CATEGORY_EXPORTS["permutations"]
__all__ = sorted(_PUBLIC)


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
