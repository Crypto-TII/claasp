"""Compatibility imports for MILP monomial models."""

from claasp.representations.constraints.milp.components.monomial import (
    MonomialTransitionMILPModel as _MonomialTransitionMILPModel,
)
from claasp.representations.constraints.milp.lowering import (
    BooleanMonomialGraphMILPModel as _BooleanMonomialGraphMILPModel,
)
from claasp.representations.constraints.milp.trails import (
    PresentMonomialTrailMILPModel as _PresentMonomialTrailMILPModel,
)

BooleanMonomialGraphMILPModel = _BooleanMonomialGraphMILPModel
MonomialTransitionMILPModel = _MonomialTransitionMILPModel
PresentMonomialTrailMILPModel = _PresentMonomialTrailMILPModel
