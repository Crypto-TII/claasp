"""Gimli permutation family and retained realizations."""

from claasp.graph import RealizationMaturity
from claasp.primitives._realizations import realization, register_realizations

from .primitive import Gimli
from .sbox import GimliSbox

register_realizations(
    Gimli,
    (
        (
            realization(
                "word",
                "word_semantics",
                structure=("word", "logical_ops"),
                description="direct word-oriented Gimli graph",
                priority=0,
                provenance=("Gimli specification",),
            ),
            Gimli,
        ),
        (
            realization(
                "legacy_sbox",
                "sbox_semantics",
                structure=("bit", "lookup_sbox"),
                description="legacy-regression S-box form",
                priority=20,
                maturity=RealizationMaturity.LEGACY_REGRESSION,
                provenance=("legacy CLAASP regression; non-canonical form",),
            ),
            GimliSbox,
        ),
    ),
)

__all__ = ["Gimli", "GimliSbox"]
