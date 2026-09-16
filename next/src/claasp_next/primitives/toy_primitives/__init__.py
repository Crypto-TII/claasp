"""Explicitly nonstandard primitives for teaching and semantic fixtures."""

from claasp_next.primitives.toy_primitives.cipherfour import CipherFour
from claasp_next.primitives.toy_primitives.fancy import Fancy
from claasp_next.primitives.toy_primitives.heys import Heys
from claasp_next.primitives.toy_primitives.speck import ToySpeck
from claasp_next.primitives.toy_primitives.toyaes import ToyAES
from claasp_next.primitives.toy_primitives.toyfeistel import ToyFeistel
from claasp_next.primitives.toy_primitives.toyspn1 import ToySPN1
from claasp_next.primitives.toy_primitives.toyspn2 import ToySPN2

__all__ = [
    "CipherFour", "Fancy", "Heys", "ToyAES", "ToyFeistel", "ToySpeck",
    "ToySPN1", "ToySPN2",
]
