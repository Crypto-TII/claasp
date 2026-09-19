"""KATAN primitive family and retained realizations."""

from claasp_next.primitives._realizations import realization, register_realizations

from .fsr import KatanFSR
from .primitive import Katan

register_realizations(
    Katan,
    (
        (
            realization(
                "bitsliced",
                "boolean_semantics",
                structure=("bit", "logical_feedback"),
                description="explicit Boolean KATAN round graph",
                priority=0,
                provenance=("KATAN specification",),
            ),
            Katan,
        ),
        (
            realization(
                "feedback_register",
                "feedback_register_semantics",
                structure=("bit", "feedback_register"),
                description="KATAN graph using typed feedback registers",
                priority=10,
                provenance=("KATAN specification", "legacy CLAASP regression"),
            ),
            KatanFSR,
        ),
    ),
)

__all__ = ["Katan", "KatanFSR"]
