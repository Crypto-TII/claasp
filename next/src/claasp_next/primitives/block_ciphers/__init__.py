"""Keyed block-primitive graphs."""

from claasp_next.primitives.block_ciphers.aes import AES128, AES
from claasp_next.primitives.block_ciphers.present import Present80, Present
from claasp_next.primitives.block_ciphers.speck import Speck
from claasp_next.primitives.block_ciphers.simon import Simon

__all__ = [
    "AES128",
    "AES",
    "Present80",
    "Present",
    "Speck",
    "Simon",
]
