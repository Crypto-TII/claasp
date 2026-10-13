"""Keyed fixed-length functions that need not be permutations."""

from claasp.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export
from claasp.primitives.block_functions.trivium import (
    TriviumKeystreamFunction as TriviumKeystreamFunction,
)

_PUBLIC = CATEGORY_EXPORTS["block_functions"]
__all__ = sorted({"TriviumKeystreamFunction"} | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
