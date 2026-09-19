"""Keccak permutation family and retained realizations."""

from claasp_next.primitives._realizations import realization, register_realizations

from .invertible import KeccakInvertible
from .primitive import Keccak
from .sbox import KeccakSbox

register_realizations(
    Keccak,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_chi", "theta"),
                description="bitsliced Keccak-f graph",
                priority=0,
                provenance=("FIPS 202",),
            ),
            Keccak,
        ),
        (
            realization(
                "sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "theta"),
                description="lookup-S-box Keccak-f graph",
                priority=10,
                provenance=("FIPS 202", "legacy CLAASP regression"),
            ),
            KeccakSbox,
        ),
    ),
)

__all__ = ["Keccak", "KeccakInvertible", "KeccakSbox"]
