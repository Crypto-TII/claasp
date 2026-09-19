"""Typed tweakable block primitives."""

from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

from .threefish import Threefish as Threefish
from .trax import TRAX as TRAX
from .trax import Trax as Trax

_PUBLIC = CATEGORY_EXPORTS["tweakable_block_ciphers"]
__all__ = sorted({"TRAX", "Threefish", "Trax"} | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
