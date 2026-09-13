"""Constraint-programming representations."""

from claasp_next.representations.constraints.cp.model import MiniZincModel
from claasp_next.representations.constraints.cp.lowering import BooleanMiniZincLowerer

__all__ = [
    "BooleanMiniZincLowerer", "MiniZincModel", "PresentDifferentialCPModel",
    "PresentLinearCPModel", "SBoxDifferenceCPModel", "SpeckDifferentialCPModel",
    "SpeckTruncatedCPModel",
]


def __getattr__(name: str):
    """Load trail models lazily to avoid representation import cycles."""

    if name == "PresentDifferentialCPModel":
        from claasp_next.representations.constraints.cp.trails import PresentDifferentialCPModel

        return PresentDifferentialCPModel
    if name == "PresentLinearCPModel":
        from claasp_next.representations.constraints.cp.trails import PresentLinearCPModel

        return PresentLinearCPModel
    if name == "SpeckDifferentialCPModel":
        from claasp_next.representations.constraints.cp.trails import SpeckDifferentialCPModel

        return SpeckDifferentialCPModel
    if name in {"SBoxDifferenceCPModel", "SpeckTruncatedCPModel"}:
        from claasp_next.representations.constraints.cp import trails

        return getattr(trails, name)
    raise AttributeError(name)
