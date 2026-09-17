"""Spongent-pi permutation family and retained realizations."""

from .primitive import SpongentPi
from .fsr import SpongentPiFSR
from .precomputation import SpongentPiPrecomputation
from claasp_next.primitives._realizations import realization, register_realizations

register_realizations(SpongentPi, (
    (realization("direct", "sbox_semantics", structure=("bit", "lookup_sbox", "computed_constants"), description="direct Spongent-pi graph", priority=0, provenance=("Spongent specification",)), SpongentPi),
    (realization("precomputation", "sbox_semantics", structure=("bit", "lookup_sbox", "precomputed_constants"), description="Spongent-pi graph with precomputed round constants", priority=10, provenance=("Spongent specification", "legacy CLAASP regression")), SpongentPiPrecomputation),
))

__all__ = ["SpongentPi", "SpongentPiFSR", "SpongentPiPrecomputation"]
