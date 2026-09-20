"""KTANTAN primitive family and retained realizations."""

from claasp.primitives._realizations import realization, register_realizations

from .fsr import KtantanFSR
from .primitive import Ktantan

register_realizations(
    Ktantan,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_feedback"),
                description="explicit Boolean KTANTAN round graph",
                priority=0,
                provenance=("KTANTAN specification",),
            ),
            Ktantan,
        ),
        (
            realization(
                "feedback_register",
                "feedback_register_semantics",
                structure=("bit", "feedback_register"),
                description="KTANTAN graph using typed feedback registers",
                priority=10,
                provenance=("KTANTAN specification", "legacy CLAASP regression"),
            ),
            KtantanFSR,
        ),
    ),
)

__all__ = ["Ktantan", "KtantanFSR"]
