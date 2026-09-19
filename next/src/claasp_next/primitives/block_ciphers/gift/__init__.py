"""GIFT primitive family and retained realizations."""

from claasp_next.primitives._realizations import realization, register_realizations

from .primitive import Gift
from .sbox import GiftSbox

register_realizations(
    Gift,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_sbox"),
                description="bitsliced Boolean GIFT graph",
                priority=0,
                provenance=("GIFT specification",),
            ),
            Gift,
        ),
        (
            realization(
                "sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox"),
                description="lookup-S-box GIFT graph",
                priority=10,
                provenance=("GIFT specification", "legacy CLAASP regression"),
            ),
            GiftSbox,
        ),
    ),
)

__all__ = ["Gift", "GiftSbox"]
