"""Backend-specific functional SAT component encodings."""

from claasp.representations.constraints.sat.components.boolean import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
)
from claasp.representations.constraints.sat.components.modular_add import (
    ModularAddDeterministicTruncatedSATModel,
    ModularAddDifferentialSATModel,
    ModularAddFunctionalSATModel,
    ModularAddLinearSATModel,
    ModularAddNativeXorSATModel,
    ModularAddNWindowSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
)
from claasp.representations.constraints.sat.components.sbox import (
    SBoxFunctionalSATModel,
    SBoxTransitionSATModel,
    SBoxXorDifferentialSATModel,
    SBoxXorLinearSATModel,
)
from claasp.representations.constraints.sat.components.semi_deterministic import (
    ModularAddSemiDeterministicTruncatedSATModel,
)
from claasp.representations.constraints.sat.components.truncated import (
    ImpossibleBoundarySATModel,
    ProbabilisticTruncatedModularAddSATModel,
)
from claasp.representations.constraints.sat.components.wiring import WiringFunctionalSATModel

__all__ = [
    "BooleanFunctionalSATModel",
    "BooleanNativeXorSATModel",
    "ImpossibleBoundarySATModel",
    "ModularAddDifferentialSATModel",
    "ModularAddDeterministicTruncatedSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
    "ModularAddNWindowSATModel",
    "ModularAddSemiDeterministicTruncatedSATModel",
    "ModularSubtractDeterministicTruncatedSATModel",
    "ProbabilisticTruncatedModularAddSATModel",
    "SBoxFunctionalSATModel",
    "SBoxTransitionSATModel",
    "SBoxXorDifferentialSATModel",
    "SBoxXorLinearSATModel",
    "WiringFunctionalSATModel",
]
