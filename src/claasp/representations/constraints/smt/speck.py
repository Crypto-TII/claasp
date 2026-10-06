"""Compatibility import for the Speck SMT trail model."""

from claasp.representations.constraints.smt.trails import (
    SpeckLinearSMTModel as _SpeckLinearSMTModel,
)

SpeckLinearSMTModel = _SpeckLinearSMTModel
