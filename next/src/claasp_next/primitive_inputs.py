"""Conventional primitive categories and input-role names.

The strings are metadata and boundary names only; unlike the v4 name-mapping
module they do not select evaluator or model implementations.
"""

from claasp_next.graph.bit_builder import (
    BLOCK_CIPHER, HASH_FUNCTION, INPUT_BLOCK_COUNT, INPUT_FRAME,
    INPUT_INITIALIZATION_VECTOR, INPUT_KEY, INPUT_MESSAGE, INPUT_NONCE,
    INPUT_PLAINTEXT, INPUT_STATE, INPUT_TWEAK, INTERMEDIATE_OUTPUT, PERMUTATION,
    STREAM_CIPHER, TWEAKABLE_BLOCK_CIPHER,
)

__all__ = [name for name in globals() if name.isupper()]
