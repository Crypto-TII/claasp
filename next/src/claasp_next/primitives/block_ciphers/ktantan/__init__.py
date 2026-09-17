"""KTANTAN primitive family and retained realizations."""

from .primitive import Ktantan
from .fsr import KtantanFSR
from claasp_next.primitives._realizations import realization, register_realizations

register_realizations(Ktantan, (
    (realization("bitsliced", "boolean_semantics", structure=("bit", "logical_feedback"), description="explicit Boolean KTANTAN round graph", priority=0, provenance=("KTANTAN specification",)), Ktantan),
    (realization("feedback_register", "feedback_register_semantics", structure=("bit", "feedback_register"), description="KTANTAN graph using typed feedback registers", priority=10, provenance=("KTANTAN specification", "legacy CLAASP regression")), KtantanFSR),
))

__all__ = ["Ktantan", "KtantanFSR"]
