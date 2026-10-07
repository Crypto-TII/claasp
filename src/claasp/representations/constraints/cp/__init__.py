"""Public constraint-programming model representations."""

from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel

__all__ = [
    "BooleanMiniZincLowerer",
    "ImpossibleBoundaryCPModel",
    "MiniZincModel",
    "ModularAddDeterministicTruncatedCPModel",
    "PresentDifferentialCPModel",
    "PresentLinearCPModel",
    "ProbabilisticTruncatedModularAddCPModel",
    "SBoxBoomerangCPModel",
    "SBoxDifferenceCPModel",
    "SBoxXorDifferentialCPModel",
    "SimonImpossibleCPModel",
    "SpeckDifferentialCPModel",
    "SpeckImpossibleCPModel",
    "SpeckProbabilisticTruncatedCPModel",
    "SpeckSemiDeterministicTruncatedCPModel",
    "SpeckTruncatedCPModel",
    "WordwiseDifferenceCPModel",
    "WordDeterministicTruncatedCPModel",
    "WordDeterministicDifferentialLinearCPModel",
    "WordDifferentialCPModel",
    "WordLinearCPModel",
    "WordSemiDeterministicDifferentialLinearCPModel",
]


def __getattr__(name: str):
    """Load trail models lazily to avoid representation import cycles."""

    if name == "PresentDifferentialCPModel":
        from claasp.representations.constraints.cp.trails import PresentDifferentialCPModel

        return PresentDifferentialCPModel
    if name == "PresentLinearCPModel":
        from claasp.representations.constraints.cp.trails import PresentLinearCPModel

        return PresentLinearCPModel
    if name == "SpeckDifferentialCPModel":
        from claasp.representations.constraints.cp.trails import SpeckDifferentialCPModel

        return SpeckDifferentialCPModel
    if name in {
        "ImpossibleBoundaryCPModel",
        "ModularAddDeterministicTruncatedCPModel",
        "SBoxDifferenceCPModel",
        "SBoxBoomerangCPModel",
        "ProbabilisticTruncatedModularAddCPModel",
        "SimonImpossibleCPModel",
        "SpeckImpossibleCPModel",
        "SpeckProbabilisticTruncatedCPModel",
        "SpeckSemiDeterministicTruncatedCPModel",
        "SpeckTruncatedCPModel",
        "WordwiseDifferenceCPModel",
        "WordDeterministicTruncatedCPModel",
        "WordDeterministicDifferentialLinearCPModel",
        "WordDifferentialCPModel",
        "WordLinearCPModel",
        "WordSemiDeterministicDifferentialLinearCPModel",
    }:
        from claasp.representations.constraints.cp import trails

        return getattr(trails, name)
    if name == "SBoxXorDifferentialCPModel":
        from claasp.representations.constraints.cp.components import (
            SBoxXorDifferentialCPModel,
        )

        return SBoxXorDifferentialCPModel
    raise AttributeError(name)
