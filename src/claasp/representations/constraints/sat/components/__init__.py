"""Backend-specific functional SAT component encodings."""

from claasp.representations.constraints.sat.components.boolean import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
)
from claasp.representations.constraints.sat.components.differential_linear import (
    DifferentialToTruncatedSATModel,
    TruncatedToLinearSATModel,
)
from claasp.representations.constraints.sat.components.modular_add import (
    ModularAddDeterministicTruncatedSATModel,
    ModularAddDifferentialSATModel,
    ModularAddFunctionalSATModel,
    ModularAddLinearSATModel,
    ModularAddNativeXorSATModel,
    ModularAddNWindowSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
    ModularSubtractFunctionalSATModel,
    ModularSubtractNativeXorSATModel,
)
from claasp.representations.constraints.sat.components.modular_multiply import (
    ModularMultiplyFunctionalSATModel,
    ModularMultiplyNativeXorSATModel,
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
from claasp.representations.constraints.sat.components.wiring import (
    VariableWiringFunctionalSATModel,
    WiringFunctionalSATModel,
)

__all__ = [
    "BooleanFunctionalSATModel",
    "BooleanNativeXorSATModel",
    "DifferentialToTruncatedSATModel",
    "ImpossibleBoundarySATModel",
    "ModularAddDifferentialSATModel",
    "ModularAddDeterministicTruncatedSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
    "ModularAddNWindowSATModel",
    "ModularAddSemiDeterministicTruncatedSATModel",
    "ModularMultiplyFunctionalSATModel",
    "ModularMultiplyNativeXorSATModel",
    "ModularSubtractDeterministicTruncatedSATModel",
    "ModularSubtractFunctionalSATModel",
    "ModularSubtractNativeXorSATModel",
    "ProbabilisticTruncatedModularAddSATModel",
    "SBoxFunctionalSATModel",
    "SBoxTransitionSATModel",
    "SBoxXorDifferentialSATModel",
    "SBoxXorLinearSATModel",
    "TruncatedToLinearSATModel",
    "VariableWiringFunctionalSATModel",
    "WiringFunctionalSATModel",
]
