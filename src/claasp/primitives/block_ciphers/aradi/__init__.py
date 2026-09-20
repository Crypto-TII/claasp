"""Aradi primitive family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .primitive import Aradi
from .sbox import AradiSBox
from .sbox_compact_linear_map import AradiSBoxCompactLinearMap

register_realizations(
    Aradi,
    (
        (
            realization(
                "word",
                "word_semantics",
                structure=("word", "logical_ops"),
                description="direct word-oriented specification graph",
                priority=0,
                provenance=("Aradi specification",),
            ),
            Aradi,
        ),
        (
            realization(
                "sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox"),
                description="legacy-derived explicit S-box graph",
                priority=20,
                provenance=("legacy CLAASP regression",),
            ),
            AradiSBox,
        ),
        (
            realization(
                "sbox_compact_linear_map",
                "sbox_semantics",
                "linear_map_semantics",
                structure=("bit", "lookup_sbox", "compact_linear_map"),
                description="legacy-derived S-box graph with compact linear maps",
                priority=10,
                provenance=("legacy CLAASP regression",),
            ),
            AradiSBoxCompactLinearMap,
        ),
    ),
)

__all__ = ["Aradi", "AradiSBox", "AradiSBoxCompactLinearMap"]
