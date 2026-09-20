"""Keyed block-cipher primitive graph implementations."""

from claasp.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export
from claasp.primitives.block_ciphers.aes import AES, AES128, CustomAES
from claasp.primitives.block_ciphers.aradi import Aradi
from claasp.primitives.block_ciphers.cham import CHAM
from claasp.primitives.block_ciphers.hight import HIGHT
from claasp.primitives.block_ciphers.idea import IDEA
from claasp.primitives.block_ciphers.lea import LEA
from claasp.primitives.block_ciphers.present import Present, Present80
from claasp.primitives.block_ciphers.raiden import Raiden
from claasp.primitives.block_ciphers.rc5 import RC5
from claasp.primitives.block_ciphers.simeck import Simeck
from claasp.primitives.block_ciphers.simon import Simon
from claasp.primitives.block_ciphers.sparx import SPARX
from claasp.primitives.block_ciphers.speck import Speck
from claasp.primitives.block_ciphers.tea import TEA
from claasp.primitives.block_ciphers.threefish import Threefish
from claasp.primitives.block_ciphers.trax import TRAX
from claasp.primitives.block_ciphers.xtea import XTEA

__all__ = [
    "AES",
    "AES128",
    "CHAM",
    "HIGHT",
    "IDEA",
    "LEA",
    "RC5",
    "SPARX",
    "TEA",
    "TRAX",
    "XTEA",
    "Aradi",
    "CustomAES",
    "Present",
    "Present80",
    "Raiden",
    "Simeck",
    "Simon",
    "Speck",
    "Threefish",
]

_PUBLIC = CATEGORY_EXPORTS["block_ciphers"]
__all__ = sorted(set(__all__) | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
