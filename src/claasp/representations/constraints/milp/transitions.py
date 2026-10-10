"""Compatibility import for modular-addition MILP component models."""

from claasp.representations.constraints.milp.components.modular_add import (
    ModularAddLinearMILPModel as _ModularAddLinearMILPModel,
)

ModularAddLinearMILPModel = _ModularAddLinearMILPModel
