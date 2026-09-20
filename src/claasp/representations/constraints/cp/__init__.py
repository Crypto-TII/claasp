"""Public constraint-programming model representations."""

from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel

__all__ = [
    "BooleanMiniZincLowerer",
    "ImpossibleBoundaryCPModel",
    "MiniZincModel",
    "PresentDifferentialCPModel",
    "PresentLinearCPModel",
    "ProbabilisticTruncatedModularAddCPModel",
    "SBoxBoomerangCPModel",
    "SBoxDifferenceCPModel",
    "SimonImpossibleCPModel",
    "SpeckDifferentialCPModel",
    "SpeckImpossibleCPModel",
    "SpeckProbabilisticTruncatedCPModel",
    "SpeckTruncatedCPModel",
    "WordwiseDifferenceCPModel",
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
        "SBoxDifferenceCPModel",
        "SBoxBoomerangCPModel",
        "ProbabilisticTruncatedModularAddCPModel",
        "SimonImpossibleCPModel",
        "SpeckImpossibleCPModel",
        "SpeckProbabilisticTruncatedCPModel",
        "SpeckTruncatedCPModel",
        "WordwiseDifferenceCPModel",
    }:
        from claasp.representations.constraints.cp import trails

        return getattr(trails, name)
    raise AttributeError(name)
