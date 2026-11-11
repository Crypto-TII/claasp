"""Poseidon primitive, parameter catalogue, provenance, and supporting data."""

from claasp._catalogue_metadata import _entry

from .parameters import PoseidonParameterSet, poseidon_bn254_width3
from .primitive import Poseidon

__all__ = ["Poseidon", "PoseidonParameterSet", "poseidon_bn254_width3"]


__catalogue__ = (
    _entry(
        "primitive",
        Poseidon,
        evidence=("tests/unit/primitives/permutations/poseidon/test_package.py",),
        example={
            "modulus": 17,
            "exponent": 3,
            "full_rounds": 2,
            "partial_rounds": 1,
            "round_constants": ((1, 2), (3, 4), (5, 6)),
            "linear_layer": ((1, 1), (1, 2)),
        },
    ),
)
