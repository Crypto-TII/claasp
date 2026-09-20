"""uBlock primitive family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .primitive import Ublock
from .single_linear_layer import UblockSingleLinearLayer

register_realizations(
    Ublock,
    (
        (
            realization(
                "decomposed_linear_layer",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "decomposed_linear_layer"),
                description="uBlock graph with decomposed linear layers",
                priority=0,
                provenance=("uBlock specification",),
            ),
            Ublock,
        ),
        (
            realization(
                "single_linear_layer",
                "sbox_semantics",
                "linear_map_semantics",
                structure=("bit", "lookup_sbox", "single_linear_layer"),
                description="uBlock graph with consolidated linear layers",
                priority=10,
                provenance=("uBlock specification", "legacy CLAASP regression"),
            ),
            UblockSingleLinearLayer,
        ),
    ),
)

__all__ = ["Ublock", "UblockSingleLinearLayer"]
