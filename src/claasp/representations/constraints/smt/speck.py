"""Compatibility import for the Speck SMT trail model."""

from claasp.representations.constraints.smt.trails import (
    SpeckXorLinearSMTModel as _SpeckXorLinearSMTModel,
)

SpeckXorLinearSMTModel = _SpeckXorLinearSMTModel
