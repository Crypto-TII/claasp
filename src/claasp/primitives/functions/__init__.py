"""Unkeyed fixed-length primitive functions."""

from claasp.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export
from claasp.primitives.functions.blake import BlakeCompressionFunction as BlakeCompressionFunction
from claasp.primitives.functions.blake2 import (
    Blake2CompressionFunction as Blake2CompressionFunction,
)
from claasp.primitives.functions.bluetooth_e0 import (
    BluetoothE0KeystreamFunction as BluetoothE0KeystreamFunction,
)
from claasp.primitives.functions.md5 import MD5SingleBlockFunction as MD5SingleBlockFunction
from claasp.primitives.functions.sha1 import SHA1SingleBlockFunction as SHA1SingleBlockFunction
from claasp.primitives.functions.sha2 import SHA2SingleBlockFunction as SHA2SingleBlockFunction
from claasp.primitives.functions.whirlpool import (
    WhirlpoolSingleBlockFunction as WhirlpoolSingleBlockFunction,
)

_PUBLIC = CATEGORY_EXPORTS["functions"]
__all__ = sorted(_PUBLIC)


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
