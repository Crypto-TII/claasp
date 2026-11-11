"""Canonical tweakable-primitives import for TRAX-L."""

from claasp._catalogue_metadata import _entry
from claasp.primitives.block_ciphers.trax import TRAX

Trax = TRAX

__all__ = ["TRAX", "Trax"]


__catalogue__ = (_entry("primitive", Trax, name="Trax"),)
