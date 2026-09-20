"""Convenience re-exports for the Poseidon-owned parameter catalogue."""

from claasp.primitives.permutations.poseidon.parameters import (
    PoseidonParameterSet,
    poseidon_bn254_width3,
)

__all__ = ["PoseidonParameterSet", "poseidon_bn254_width3"]
