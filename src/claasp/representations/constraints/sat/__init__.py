"""Dependency-free Boolean/CNF constraint representations."""

from claasp.representations.constraints.sat.components import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
    ImpossibleBoundarySATModel,
    ModularAddDeterministicTruncatedSATModel,
    ModularAddDifferentialSATModel,
    ModularAddFunctionalSATModel,
    ModularAddLinearSATModel,
    ModularAddNativeXorSATModel,
    ModularAddNWindowSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
    SBoxFunctionalSATModel,
    SBoxTransitionSATModel,
    SBoxXorDifferentialSATModel,
    SBoxXorLinearSATModel,
    WiringFunctionalSATModel,
)
from claasp.representations.constraints.sat.exporters import CryptoMiniSatDimacsExporter
from claasp.representations.constraints.sat.lowering import BooleanCNFModel, BooleanNativeXorModel
from claasp.representations.constraints.sat.model import CNFFormula, NativeXorCNFFormula
from claasp.representations.constraints.sat.trails import (
    NWindowSATStrategy,
    WordDeterministicTruncatedCharacteristic,
    WordDeterministicTruncatedEnumeration,
    WordDeterministicTruncatedSATModel,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
    WordLinearSATModel,
)

__all__ = [
    "BooleanCNFModel",
    "BooleanNativeXorModel",
    "BooleanFunctionalSATModel",
    "BooleanNativeXorSATModel",
    "CNFFormula",
    "CryptoMiniSatDimacsExporter",
    "ImpossibleBoundarySATModel",
    "ModularAddDifferentialSATModel",
    "ModularAddDeterministicTruncatedSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
    "ModularAddNWindowSATModel",
    "ModularSubtractDeterministicTruncatedSATModel",
    "NWindowSATStrategy",
    "NativeXorCNFFormula",
    "SBoxFunctionalSATModel",
    "SBoxTransitionSATModel",
    "SBoxXorDifferentialSATModel",
    "SBoxXorLinearSATModel",
    "WiringFunctionalSATModel",
    "WordDeterministicTruncatedCharacteristic",
    "WordDeterministicTruncatedEnumeration",
    "WordDeterministicTruncatedSATModel",
    "WordDifferentialSATModel",
    "WordDifferentialNativeXorSATModel",
    "WordLinearSATModel",
    "WordLinearNativeXorSATModel",
]
