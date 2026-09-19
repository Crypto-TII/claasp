"""Unkeyed fixed-length primitive functions."""

from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export
from claasp_next.primitives.functions.blake import Blake as Blake
from claasp_next.primitives.functions.blake2 import Blake2 as Blake2
from claasp_next.primitives.functions.bluetooth_e0 import BluetoothE0 as BluetoothE0
from claasp_next.primitives.functions.md5 import MD5 as MD5
from claasp_next.primitives.functions.sha1 import SHA1 as SHA1
from claasp_next.primitives.functions.sha2 import SHA2 as SHA2
from claasp_next.primitives.functions.whirlpool import Whirlpool as Whirlpool

_PUBLIC = CATEGORY_EXPORTS["functions"]
__all__ = sorted(_PUBLIC)


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
