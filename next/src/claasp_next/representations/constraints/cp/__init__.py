"""Constraint-programming representations."""

from claasp_next.representations.constraints.cp.model import MiniZincModel
from claasp_next.representations.constraints.cp.lowering import BooleanMiniZincLowerer

__all__ = ["BooleanMiniZincLowerer", "MiniZincModel", "PresentDifferentialCPModel"]


def __getattr__(name: str):
    """Load trail models lazily to avoid representation import cycles."""

    if name == "PresentDifferentialCPModel":
        from claasp_next.representations.constraints.cp.trails import PresentDifferentialCPModel

        return PresentDifferentialCPModel
    raise AttributeError(name)
