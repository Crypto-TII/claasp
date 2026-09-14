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
from claasp_next.semantics.cryptanalysis import (
    BitPattern,
    ModularAddTransitionSemantics,
    ModularAddLinearSemantics,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)
from claasp_next.analysis.truncated import (
    TruncatedBit,
    TruncatedXorDifference,
    propagate_two_word_speck_round,
    truncated_modular_add,
)
from claasp_next.analysis.targets import AttackTarget
from claasp_next.analysis.boomerang import (
    BoomerangExperimentResult,
    run_speck32_boomerang_experiment,
)
from claasp_next.analysis.composed import (
    DifferentialLinearFixture,
    check_speck32_differential_linear_fixture,
    speck32_differential_linear_legacy_fixture,
)

__all__ = [
    "Analysis",
    "AttackTarget",
    "AnalysisProblem",
    "AnalysisResult",
    "Equal",
    "FixedValue",
    "HammingWeight",
    "MinimizeWeight",
    "Nonzero",
    "NotEqual",
    "BitPattern",
    "ModularAddTransitionSemantics",
    "ModularAddLinearSemantics",
    "SBoxTransitionSemantics",
    "Trail",
    "TrailKind",
    "TrailSearchResult",
    "TrailStep",
    "Transition",
    "XorDifference",
    "XorMask",
    "TruncatedBit",
    "TruncatedXorDifference",
    "propagate_two_word_speck_round",
    "truncated_modular_add",
    "BoomerangExperimentResult",
    "run_speck32_boomerang_experiment",
    "DifferentialLinearFixture",
    "check_speck32_differential_linear_fixture",
    "speck32_differential_linear_legacy_fixture",
]
