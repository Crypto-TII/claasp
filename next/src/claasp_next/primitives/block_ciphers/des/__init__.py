"""DES primitive family and boundary realizations."""

from claasp_next.primitives._realizations import realization, register_realizations

from .exact_key_length import DESExactKeyLength
from .primitive import DES

register_realizations(
    DES,
    (
        (
            realization(
                "parity_key",
                "sbox_semantics",
                structure=("bit", "lookup_sbox"),
                description="DES graph with the specified parity-bearing 64-bit key boundary",
                priority=0,
                provenance=("FIPS 46-3",),
            ),
            DES,
        ),
    ),
)

__all__ = ["DES", "DESExactKeyLength"]
