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
    ModularAddDeterministicTruncatedCPModel,
)

__all__ = [
    "ModularAddDeterministicTruncatedCPModel",
    "ModularAddBoomerangCPModel",
    "ProbabilisticTruncatedModularAddCPModel",
    "SBoxBoomerangCPModel",
    "SBoxDifferenceCPModel",
    "SBoxXorDifferentialCPModel",
]
