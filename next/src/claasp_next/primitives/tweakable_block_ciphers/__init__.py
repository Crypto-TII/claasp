"""Typed tweakable block primitives."""

from .threefish import Threefish
from .trax import TRAX, Trax
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

_PUBLIC = CATEGORY_EXPORTS["tweakable_block_ciphers"]
__all__ = sorted({"TRAX", "Threefish", "Trax"} | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
