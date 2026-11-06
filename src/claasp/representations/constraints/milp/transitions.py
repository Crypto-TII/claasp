"""Compatibility import for modular-addition MILP component models."""

from claasp.representations.constraints.milp.components.modular_add import (
    ModularAddXorLinearMILPModel as _ModularAddXorLinearMILPModel,
)

ModularAddXorLinearMILPModel = _ModularAddXorLinearMILPModel
