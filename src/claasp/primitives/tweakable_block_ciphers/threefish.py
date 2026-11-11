"""Canonical tweakable-primitives import for Threefish."""

from claasp._catalogue_metadata import _entry
from claasp.primitives.block_ciphers.threefish import Threefish

__all__ = ["Threefish"]


__catalogue__ = (_entry("primitive", Threefish),)
