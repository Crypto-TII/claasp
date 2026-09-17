"""Simon primitive family and retained realizations."""

from .primitive import Simon
from .sbox import SimonSbox
from claasp_next.graph import RealizationMaturity
from claasp_next.primitives._realizations import realization, register_realizations

register_realizations(Simon, (
    (realization("word", "word_semantics", structure=("word", "logical_ops"), description="direct word-oriented Simon graph", priority=0, provenance=("Simon specification",)), Simon),
    (realization("legacy_sbox", "sbox_semantics", structure=("bit", "lookup_sbox"), description="legacy-regression S-box form", priority=20, maturity=RealizationMaturity.LEGACY_REGRESSION, provenance=("legacy CLAASP regression; non-canonical form",)), SimonSbox),
))

__all__ = ["Simon", "SimonSbox"]
