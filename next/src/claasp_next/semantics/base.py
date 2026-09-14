"""Semantic types applied to typed primitive graphs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SemanticType:
    """What values or abstract properties mean while flowing through a graph.

    Semantic types describe meaning, not an encoding or a solver. Researchers
    may define additional semantic types without changing representation
    compilers.
    """

    name: str
    description: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "a").isalnum():
            raise ValueError("semantic type name must be a non-empty identifier")
        if not self.description:
            raise ValueError("semantic type description must not be empty")


CONCRETE = SemanticType("concrete", "Concrete logical-unit values")
XOR_DIFFERENTIAL = SemanticType("xor_differential", "XOR differences and probabilities")
XOR_LINEAR = SemanticType("xor_linear", "XOR masks and signed correlations")
DETERMINISTIC_TRUNCATED_XOR = SemanticType(
    "deterministic_truncated_xor",
    "Three-valued deterministic XOR differences",
)
PROBABILISTIC_TRUNCATED_XOR = SemanticType(
    "probabilistic_truncated_xor",
    "Partial XOR differences with probability weights",
)
SYMBOLIC = SemanticType("symbolic", "Abstract symbolic values")
LEAKAGE = SemanticType("leakage", "Simulated side-channel observations")
