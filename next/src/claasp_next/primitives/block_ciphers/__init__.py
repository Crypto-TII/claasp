"""Keyed block-primitive graphs."""

from claasp_next.primitives.block_ciphers.aes import AES128, AES, CustomAES
from claasp_next.primitives.block_ciphers.aradi import Aradi
from claasp_next.primitives.block_ciphers.cham import CHAM
from claasp_next.primitives.block_ciphers.hight import HIGHT
from claasp_next.primitives.block_ciphers.idea import IDEA
from claasp_next.primitives.block_ciphers.lea import LEA
from claasp_next.primitives.block_ciphers.present import Present80, Present
from claasp_next.primitives.block_ciphers.raiden import Raiden
from claasp_next.primitives.block_ciphers.rc5 import RC5
from claasp_next.primitives.block_ciphers.simeck import Simeck
from claasp_next.primitives.block_ciphers.sparx import SPARX
from claasp_next.primitives.block_ciphers.speck import Speck
from claasp_next.primitives.block_ciphers.simon import Simon
from claasp_next.primitives.block_ciphers.tea import TEA
from claasp_next.primitives.block_ciphers.threefish import Threefish
from claasp_next.primitives.block_ciphers.trax import TRAX
from claasp_next.primitives.block_ciphers.xtea import XTEA
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

__all__ = [
    "AES128",
    "AES",
    "CustomAES",
    "Aradi",
    "CHAM",
    "HIGHT",
    "IDEA",
    "LEA",
    "Present80",
    "Present",
    "Raiden",
    "RC5",
    "Simeck",
    "SPARX",
    "Speck",
    "Simon",
    "TEA",
    "Threefish",
    "TRAX",
    "XTEA",
]

_PUBLIC = CATEGORY_EXPORTS["block_ciphers"]
__all__ = sorted(set(__all__) | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
