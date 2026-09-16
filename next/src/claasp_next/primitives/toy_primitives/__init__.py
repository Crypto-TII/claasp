"""Explicitly nonstandard primitives for teaching and semantic fixtures."""

from claasp_next.primitives.toy_primitives.cipherfour import CipherFour
from claasp_next.primitives.toy_primitives.fancy import Fancy
from claasp_next.primitives.toy_primitives.heys import Heys
from claasp_next.primitives.toy_primitives.speck import ToySpeck
from claasp_next.primitives.toy_primitives.toyaes import ToyAES
from claasp_next.primitives.toy_primitives.toyfeistel import ToyFeistel
from claasp_next.primitives.toy_primitives.toyspn1 import ToySPN1
from claasp_next.primitives.toy_primitives.toyspn2 import ToySPN2
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

__all__ = [
    "CipherFour", "Fancy", "Heys", "ToyAES", "ToyFeistel", "ToySpeck",
    "ToySPN1", "ToySPN2",
]

_PUBLIC = CATEGORY_EXPORTS["toy_primitives"]
__all__ = sorted(set(__all__) | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
