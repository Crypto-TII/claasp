"""Conventional primitive categories and input-role names.

The strings are metadata and boundary names only; unlike the v4 name-mapping
module they do not select evaluator or model implementations.
"""

from claasp_next.graph.bit_builder import BLOCK_CIPHER as BLOCK_CIPHER
from claasp_next.graph.bit_builder import HASH_FUNCTION as HASH_FUNCTION
from claasp_next.graph.bit_builder import INPUT_BLOCK_COUNT as INPUT_BLOCK_COUNT
from claasp_next.graph.bit_builder import INPUT_FRAME as INPUT_FRAME
from claasp_next.graph.bit_builder import (
    INPUT_INITIALIZATION_VECTOR as INPUT_INITIALIZATION_VECTOR,
)
from claasp_next.graph.bit_builder import INPUT_KEY as INPUT_KEY
from claasp_next.graph.bit_builder import INPUT_MESSAGE as INPUT_MESSAGE
from claasp_next.graph.bit_builder import INPUT_NONCE as INPUT_NONCE
from claasp_next.graph.bit_builder import INPUT_PLAINTEXT as INPUT_PLAINTEXT
from claasp_next.graph.bit_builder import INPUT_STATE as INPUT_STATE
from claasp_next.graph.bit_builder import INPUT_TWEAK as INPUT_TWEAK
from claasp_next.graph.bit_builder import INTERMEDIATE_OUTPUT as INTERMEDIATE_OUTPUT
from claasp_next.graph.bit_builder import PERMUTATION as PERMUTATION
from claasp_next.graph.bit_builder import STREAM_CIPHER as STREAM_CIPHER
from claasp_next.graph.bit_builder import TWEAKABLE_BLOCK_CIPHER as TWEAKABLE_BLOCK_CIPHER

__all__ = [name for name in globals() if name.isupper()]
