"""TinyJambu primitive family and retained realizations."""

from .primitive import TinyJambu
from .word import TinyJambuWordBased
from .fsr_word import TinyJambuFSRWordBased
from claasp_next.primitives._realizations import realization, register_realizations

register_realizations(TinyJambu, (
    (realization("bitsliced", "boolean_semantics", structure=("bit", "logical_feedback"), description="bit-oriented TinyJambu graph", priority=0, provenance=("TinyJambu specification",)), TinyJambu),
    (realization("word", "word_semantics", structure=("bit_boundary", "word_operations"), description="word-oriented TinyJambu graph", priority=10, provenance=("TinyJambu specification", "legacy CLAASP regression")), TinyJambuWordBased),
    (realization("feedback_register_word", "feedback_register_semantics", "word_semantics", structure=("bit_boundary", "word_feedback_register"), description="word-oriented typed feedback-register graph", priority=20, provenance=("TinyJambu specification", "legacy CLAASP regression")), TinyJambuFSRWordBased),
))

__all__ = ["TinyJambu", "TinyJambuWordBased", "TinyJambuFSRWordBased"]
