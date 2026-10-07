"""Dependency-free Boolean/CNF constraint representations."""

from claasp.representations.constraints.sat.components import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
    ModularAddDifferentialSATModel,
    ModularAddFunctionalSATModel,
    ModularAddLinearSATModel,
    ModularAddNativeXorSATModel,
    ModularAddNWindowSATModel,
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
    WordDifferentialSATModel,
    WordLinearSATModel,
)

__all__ = [
    "BooleanCNFModel",
    "BooleanNativeXorModel",
    "BooleanFunctionalSATModel",
    "BooleanNativeXorSATModel",
    "CNFFormula",
    "CryptoMiniSatDimacsExporter",
    "ModularAddDifferentialSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
    "ModularAddNWindowSATModel",
    "NWindowSATStrategy",
    "NativeXorCNFFormula",
    "SBoxFunctionalSATModel",
    "SBoxTransitionSATModel",
    "SBoxXorDifferentialSATModel",
    "SBoxXorLinearSATModel",
    "WiringFunctionalSATModel",
    "WordDifferentialSATModel",
    "WordLinearSATModel",
]
