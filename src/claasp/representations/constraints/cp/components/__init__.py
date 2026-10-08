"""Backend-specific CP component encodings."""

from claasp.representations.constraints.cp.components.modular_add import (
    ModularAddBoomerangCPModel,
    ProbabilisticTruncatedModularAddCPModel,
)
from claasp.representations.constraints.cp.components.sbox import (
    SBoxBoomerangCPModel,
    SBoxDifferenceCPModel,
    SBoxXorDifferentialCPModel,
)
from claasp.representations.constraints.cp.components.truncated import (
    HybridImpossibleBoundaryCPModel,
    HybridImpossibleBoundaryResult,
    ModularAddDeterministicTruncatedCPModel,
)

__all__ = [
    "HybridImpossibleBoundaryCPModel",
    "HybridImpossibleBoundaryResult",
    "ModularAddDeterministicTruncatedCPModel",
    "ModularAddBoomerangCPModel",
    "ProbabilisticTruncatedModularAddCPModel",
    "SBoxBoomerangCPModel",
    "SBoxDifferenceCPModel",
    "SBoxXorDifferentialCPModel",
]
