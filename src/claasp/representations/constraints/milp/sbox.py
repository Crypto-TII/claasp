"""Compatibility imports for S-box MILP component models."""

from claasp.representations.constraints.milp.components.sbox import (
    SBoxTransitionMILPModel as _SBoxTransitionMILPModel,
)
from claasp.representations.constraints.milp.components.sbox import (
    SBoxXorDifferentialMILPModel as _SBoxXorDifferentialMILPModel,
)
from claasp.representations.constraints.milp.components.sbox import (
    SBoxXorLinearMILPModel as _SBoxXorLinearMILPModel,
)

SBoxTransitionMILPModel = _SBoxTransitionMILPModel
SBoxXorDifferentialMILPModel = _SBoxXorDifferentialMILPModel
SBoxXorLinearMILPModel = _SBoxXorLinearMILPModel
