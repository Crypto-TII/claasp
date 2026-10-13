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
from claasp.representations.constraints.milp.components.sbox_inequalities import (
    SBoxMILPInequalityGroup,
    SBoxMILPInequalityStrategy,
    SBoxMILPInequalitySystem,
    SBoxXorDifferentialConvexHullMILPModel,
    SBoxXorDifferentialEspressoMILPModel,
    SBoxXorDifferentialGreedyMILPModel,
    SBoxXorDifferentialMinimumMILPModel,
    SBoxXorLinearConvexHullMILPModel,
    SBoxXorLinearEspressoMILPModel,
    SBoxXorLinearGreedyMILPModel,
    SBoxXorLinearMinimumMILPModel,
    load_bundled_sbox_milp_inequalities,
)

SBoxTransitionMILPModel = _SBoxTransitionMILPModel
SBoxXorDifferentialMILPModel = _SBoxXorDifferentialMILPModel
SBoxXorLinearMILPModel = _SBoxXorLinearMILPModel

__all__ = [
    "SBoxMILPInequalityGroup",
    "SBoxMILPInequalityStrategy",
    "SBoxMILPInequalitySystem",
    "SBoxTransitionMILPModel",
    "SBoxXorDifferentialConvexHullMILPModel",
    "SBoxXorDifferentialEspressoMILPModel",
    "SBoxXorDifferentialGreedyMILPModel",
    "SBoxXorDifferentialMILPModel",
    "SBoxXorDifferentialMinimumMILPModel",
    "SBoxXorLinearConvexHullMILPModel",
    "SBoxXorLinearEspressoMILPModel",
    "SBoxXorLinearGreedyMILPModel",
    "SBoxXorLinearMILPModel",
    "SBoxXorLinearMinimumMILPModel",
    "load_bundled_sbox_milp_inequalities",
]
