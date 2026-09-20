"""QARMAv2 primitive family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .mixcolumn import QARMAv2MixColumn
from .primitive import QARMAv2

register_realizations(
    QARMAv2,
    (
        (
            realization(
                "permutation_linear_layer",
                "sbox_semantics",
                structure=("bit", "lookup_sbox", "permutation_linear_layer"),
                description="QARMAv2 graph with permutation-based diffusion",
                priority=0,
                provenance=("QARMAv2 specification",),
            ),
            QARMAv2,
        ),
        (
            realization(
                "mix_column",
                "sbox_semantics",
                "linear_map_semantics",
                structure=("bit", "lookup_sbox", "mix_column"),
                description="QARMAv2 graph with MixColumn diffusion",
                priority=10,
                provenance=("QARMAv2 specification", "legacy CLAASP regression"),
            ),
            QARMAv2MixColumn,
        ),
    ),
)

__all__ = ["QARMAv2", "QARMAv2MixColumn"]
