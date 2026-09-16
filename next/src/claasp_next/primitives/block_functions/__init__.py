"""Keyed fixed-length functions that need not be permutations."""

from claasp_next.primitives.block_functions.trivium import Trivium
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

_PUBLIC = CATEGORY_EXPORTS["block_functions"]
__all__ = sorted({"Trivium"} | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
