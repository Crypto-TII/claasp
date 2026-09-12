"""Backend-independent analysis problems, constraints, and results."""

from claasp_next.analysis.constraints import (
    Equal,
    FixedValue,
    HammingWeight,
    Nonzero,
    NotEqual,
)
from claasp_next.analysis.facade import Analysis, AnalysisResult
from claasp_next.analysis.problem import AnalysisProblem, MinimizeWeight
from claasp_next.analysis.trails import (
    BitPattern,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)

__all__ = [
    "Analysis",
    "AnalysisProblem",
    "AnalysisResult",
    "Equal",
    "FixedValue",
    "HammingWeight",
    "MinimizeWeight",
    "Nonzero",
    "NotEqual",
    "BitPattern",
    "SBoxTransitionSemantics",
    "Trail",
    "TrailKind",
    "TrailSearchResult",
    "TrailStep",
    "Transition",
    "XorDifference",
    "XorMask",
]
