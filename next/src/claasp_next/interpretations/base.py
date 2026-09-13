"""Semantic interpretations applied to typed cipher graphs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Interpretation:
    """A stable description of information propagated through a graph.

    Interpretations describe meaning, not an encoding or a solver. Researchers
    may define additional interpretations without changing representation
    compilers.
    """

    name: str
    description: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "a").isalnum():
            raise ValueError("interpretation name must be a non-empty identifier")
        if not self.description:
            raise ValueError("interpretation description must not be empty")


CONCRETE = Interpretation("concrete", "Concrete logical-unit values")
XOR_DIFFERENTIAL = Interpretation("xor_differential", "XOR differences and probabilities")
XOR_LINEAR = Interpretation("xor_linear", "XOR masks and signed correlations")
DETERMINISTIC_TRUNCATED_XOR = Interpretation(
    "deterministic_truncated_xor",
    "Three-valued deterministic XOR differences",
)
SYMBOLIC = Interpretation("symbolic", "Abstract symbolic values")
LEAKAGE = Interpretation("leakage", "Simulated side-channel observations")
