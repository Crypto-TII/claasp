"""Spongent-pi permutation family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .fsr import SpongentPiFSR
from .precomputation import SpongentPiPrecomputation
from .primitive import SpongentPi

register_realizations(
    SpongentPi,
    (
        (
            realization(
                "direct",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "computed_constants"),
                description="direct Spongent-pi graph",
                priority=0,
                provenance=("Spongent specification",),
            ),
            SpongentPi,
        ),
        (
            realization(
                "precomputation",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "precomputed_constants"),
                description="Spongent-pi graph with precomputed round constants",
                priority=10,
                provenance=("Spongent specification", "legacy CLAASP regression"),
            ),
            SpongentPiPrecomputation,
        ),
    ),
)

__all__ = ["SpongentPi", "SpongentPiFSR", "SpongentPiPrecomputation"]
