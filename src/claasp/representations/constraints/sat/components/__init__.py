"""Backend-specific functional SAT component encodings."""

from claasp.representations.constraints.sat.components.binary_field import (
    BinaryFieldFunctionalSATModel,
)
from claasp.representations.constraints.sat.components.boolean import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
)
from claasp.representations.constraints.sat.components.modular_add import (
    ModularAddDeterministicTruncatedSATModel,
    ModularAddFunctionalSATModel,
    ModularAddNativeXorSATModel,
    ModularAddNWindowSATModel,
    ModularAddXorDifferentialSATModel,
    ModularAddXorLinearSATModel,
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
from claasp.representations.constraints.sat.components.xor_differential_linear import (
    TruncatedToXorLinearSATModel,
    XorDifferentialToTruncatedSATModel,
)

__all__ = [
    "BinaryFieldFunctionalSATModel",
    "BooleanFunctionalSATModel",
    "BooleanNativeXorSATModel",
    "XorDifferentialToTruncatedSATModel",
    "ImpossibleBoundarySATModel",
    "ModularAddXorDifferentialSATModel",
    "ModularAddDeterministicTruncatedSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddXorLinearSATModel",
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
    "TruncatedToXorLinearSATModel",
    "VariableWiringFunctionalSATModel",
    "WiringFunctionalSATModel",
]
