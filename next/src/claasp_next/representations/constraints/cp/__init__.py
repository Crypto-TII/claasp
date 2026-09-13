"""Constraint-programming representations."""

from claasp_next.representations.constraints.cp.model import MiniZincModel
from claasp_next.representations.constraints.cp.lowering import BooleanMiniZincLowerer

__all__ = ["BooleanMiniZincLowerer", "MiniZincModel"]
