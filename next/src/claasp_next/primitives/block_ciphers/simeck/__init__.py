"""Simeck primitive family and retained realizations."""

from .primitive import Simeck
from .sbox import SimeckSbox
from claasp_next.graph import RealizationMaturity
from claasp_next.primitives._realizations import realization, register_realizations

register_realizations(Simeck, (
    (realization("word", "word_semantics", structure=("word", "logical_ops"), description="direct word-oriented Simeck graph", priority=0, provenance=("Simeck specification",)), Simeck),
    (realization("legacy_sbox", "sbox_semantics", structure=("bit", "lookup_sbox"), description="legacy-regression S-box form", priority=20, maturity=RealizationMaturity.LEGACY_REGRESSION, provenance=("legacy CLAASP regression; non-canonical form",)), SimeckSbox),
))

__all__ = ["Simeck", "SimeckSbox"]
