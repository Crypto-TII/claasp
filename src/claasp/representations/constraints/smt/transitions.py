"""Compatibility imports for SMT component transition models."""

from claasp.representations.constraints.smt.components import (
    ModularAddDifferentialSMTModel as _ModularAddDifferentialSMTModel,
)
from claasp.representations.constraints.smt.components import (
    ModularAddLinearSMTModel as _ModularAddLinearSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxTransitionSMTModel as _SBoxTransitionSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxXorDifferentialSMTModel as _SBoxXorDifferentialSMTModel,
)
from claasp.representations.constraints.smt.components import (
    SBoxXorLinearSMTModel as _SBoxXorLinearSMTModel,
)

ModularAddDifferentialSMTModel = _ModularAddDifferentialSMTModel
ModularAddLinearSMTModel = _ModularAddLinearSMTModel
SBoxTransitionSMTModel = _SBoxTransitionSMTModel
SBoxXorDifferentialSMTModel = _SBoxXorDifferentialSMTModel
SBoxXorLinearSMTModel = _SBoxXorLinearSMTModel
