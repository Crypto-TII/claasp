"""Gaston permutation family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .primitive import Gaston
from .sbox import GastonSbox
from .sbox_theta import GastonSboxTheta

register_realizations(
    Gaston,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_sbox", "decomposed_theta"),
                description="bitsliced Gaston graph",
                priority=0,
                provenance=("Gaston specification",),
            ),
            Gaston,
        ),
        (
            realization(
                "sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "decomposed_theta"),
                description="lookup-S-box Gaston graph",
                priority=20,
                provenance=("Gaston specification", "legacy CLAASP regression"),
            ),
            GastonSbox,
        ),
        (
            realization(
                "sbox_theta",
                "sbox_semantics",
                "linear_map_semantics",
                structure=("bit", "lookup_sbox", "theta_linear_map"),
                description="lookup-S-box Gaston graph with typed theta",
                priority=10,
                provenance=("Gaston specification", "legacy CLAASP regression"),
            ),
            GastonSboxTheta,
        ),
    ),
)

__all__ = ["Gaston", "GastonSbox", "GastonSboxTheta"]
