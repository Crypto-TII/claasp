"""Xoodoo permutation family and retained realizations."""

from claasp_next.primitives._realizations import realization, register_realizations

from .invertible import XoodooInvertible
from .primitive import Xoodoo
from .sbox import XoodooSbox

register_realizations(
    Xoodoo,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_chi", "theta"),
                description="bitsliced Xoodoo graph",
                priority=0,
                provenance=("Xoodoo specification",),
            ),
            Xoodoo,
        ),
        (
            realization(
                "sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "theta"),
                description="lookup-S-box Xoodoo graph",
                priority=10,
                provenance=("Xoodoo specification", "legacy CLAASP regression"),
            ),
            lambda number_of_rounds=3: XoodooSbox(number_of_rounds=number_of_rounds),
        ),
    ),
)

__all__ = ["Xoodoo", "XoodooInvertible", "XoodooSbox"]
