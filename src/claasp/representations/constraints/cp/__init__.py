"""Public constraint-programming model representations."""

from claasp.representations.constraints.cp.components import (
    HybridImpossibleBoundaryCPModel,
    HybridImpossibleBoundaryResult,
    HybridSBoxCPModel,
    HybridXorCPModel,
    ModularAddBoomerangCPModel,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel

__all__ = [
    "BooleanMiniZincLowerer",
    "HybridImpossibleBoundaryCPModel",
    "HybridImpossibleBoundaryResult",
    "HybridSBoxCPModel",
    "HybridXorCPModel",
    "ImpossibleBoundaryCPModel",
    "MiniZincModel",
    "ModularAddBoomerangCPModel",
    "ModularAddBoomerangTrailCPModel",
    "ModularAddBoomerangTrailResult",
    "ModularAddDeterministicTruncatedCPModel",
    "PresentXorDifferentialCPModel",
    "PresentFixedActiveSBoxesCPModel",
    "PresentActiveSBoxesCPModel",
    "PresentXorLinearCPModel",
    "PresentKeyScheduleXorDifferentialTrail",
    "PresentProbabilisticKeyScheduleCPModel",
    "PresentHybridImpossibleCPModel",
    "ProbabilisticTruncatedModularAddCPModel",
    "SBoxBoomerangCPModel",
    "SBoxBoomerangTrailCPModel",
    "SBoxBoomerangTrailResult",
    "SBoxDifferenceCPModel",
    "SBoxXorDifferentialCPModel",
    "SimonImpossibleCPModel",
    "SpeckBoomerangCPModel",
    "SpeckXorDifferentialCPModel",
    "SpeckARXWindowXorDifferentialCPModel",
    "SpeckContinuousHeuristicCPModel",
    "SpeckContinuousMaskOptimizationCPModel",
    "ContinuousMaskOptimizationResult",
    "SpeckImpossibleCPModel",
    "SpeckProbabilisticTruncatedCPModel",
    "SpeckSemiDeterministicTruncatedCPModel",
    "SpeckTruncatedCPModel",
    "WordwiseDifferenceCPModel",
    "WordwiseDeterministicTruncatedCPModel",
    "WordwiseImpossibleCPModel",
    "WordDeterministicTruncatedCPModel",
    "WordDeterministicXorDifferentialLinearCPModel",
    "WordXorDifferentialCPModel",
    "WordXorLinearCPModel",
    "WordImpossibleCPModel",
    "WordSemiDeterministicXorDifferentialLinearCPModel",
]


def __getattr__(name: str):
    """Load trail models lazily to avoid representation import cycles."""

    if name == "PresentXorDifferentialCPModel":
        from claasp.representations.constraints.cp.trails import PresentXorDifferentialCPModel

        return PresentXorDifferentialCPModel
    if name == "PresentActiveSBoxesCPModel":
        from claasp.representations.constraints.cp.trails import PresentActiveSBoxesCPModel

        return PresentActiveSBoxesCPModel
    if name == "PresentFixedActiveSBoxesCPModel":
        from claasp.representations.constraints.cp.trails import PresentFixedActiveSBoxesCPModel

        return PresentFixedActiveSBoxesCPModel
    if name == "PresentXorLinearCPModel":
        from claasp.representations.constraints.cp.trails import PresentXorLinearCPModel

        return PresentXorLinearCPModel
    if name == "SpeckXorDifferentialCPModel":
        from claasp.representations.constraints.cp.trails import SpeckXorDifferentialCPModel

        return SpeckXorDifferentialCPModel
    if name == "SpeckARXWindowXorDifferentialCPModel":
        from claasp.representations.constraints.cp.trails import (
            SpeckARXWindowXorDifferentialCPModel,
        )

        return SpeckARXWindowXorDifferentialCPModel
    if name in {
        "ImpossibleBoundaryCPModel",
        "ModularAddDeterministicTruncatedCPModel",
        "ModularAddBoomerangTrailCPModel",
        "ModularAddBoomerangTrailResult",
        "SBoxDifferenceCPModel",
        "SBoxBoomerangCPModel",
        "SBoxBoomerangTrailCPModel",
        "SBoxBoomerangTrailResult",
        "ProbabilisticTruncatedModularAddCPModel",
        "PresentHybridImpossibleCPModel",
        "PresentKeyScheduleXorDifferentialTrail",
        "PresentProbabilisticKeyScheduleCPModel",
        "SimonImpossibleCPModel",
        "SpeckBoomerangCPModel",
        "SpeckImpossibleCPModel",
        "SpeckContinuousHeuristicCPModel",
        "SpeckContinuousMaskOptimizationCPModel",
        "ContinuousMaskOptimizationResult",
        "SpeckProbabilisticTruncatedCPModel",
        "SpeckSemiDeterministicTruncatedCPModel",
        "SpeckTruncatedCPModel",
        "WordwiseDifferenceCPModel",
        "WordwiseDeterministicTruncatedCPModel",
        "WordwiseImpossibleCPModel",
        "WordDeterministicTruncatedCPModel",
        "WordDeterministicXorDifferentialLinearCPModel",
        "WordXorDifferentialCPModel",
        "WordXorLinearCPModel",
        "WordImpossibleCPModel",
        "WordSemiDeterministicXorDifferentialLinearCPModel",
    }:
        from claasp.representations.constraints.cp import trails

        return getattr(trails, name)
    if name == "SBoxXorDifferentialCPModel":
        from claasp.representations.constraints.cp.components import (
            SBoxXorDifferentialCPModel,
        )

        return SBoxXorDifferentialCPModel
    raise AttributeError(name)
