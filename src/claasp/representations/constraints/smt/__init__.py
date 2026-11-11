"""Dependency-free SMT constraint representations."""

from claasp._catalogue_metadata import _entry
from claasp.representations.constraints.smt.components import (
    ModularAddDeterministicTruncatedSMTModel,
    ModularAddXorDifferentialSMTModel,
    ModularAddXorLinearSMTModel,
    SBoxTransitionSMTModel,
    SBoxXorDifferentialSMTModel,
    SBoxXorLinearSMTModel,
)
from claasp.representations.constraints.smt.lowering import BooleanSMTModel
from claasp.representations.constraints.smt.model import SMTFormula
from claasp.representations.constraints.smt.trails import (
    PresentXorDifferentialSMTModel,
    PresentXorLinearSMTModel,
    SpeckXorLinearSMTModel,
    WordDeterministicTruncatedSMTModel,
)
from claasp.representations.constraints.smt.word_xor_differential import WordXorDifferentialSMTModel
from claasp.representations.constraints.smt.word_xor_linear import WordXorLinearSMTModel

__all__ = [
    "BooleanSMTModel",
    "ModularAddXorDifferentialSMTModel",
    "ModularAddDeterministicTruncatedSMTModel",
    "ModularAddXorLinearSMTModel",
    "PresentXorDifferentialSMTModel",
    "PresentXorLinearSMTModel",
    "SBoxTransitionSMTModel",
    "SBoxXorDifferentialSMTModel",
    "SBoxXorLinearSMTModel",
    "SMTFormula",
    "SpeckXorLinearSMTModel",
    "WordXorDifferentialSMTModel",
    "WordDeterministicTruncatedSMTModel",
    "WordXorLinearSMTModel",
]


__catalogue__ = (
    _entry(
        "representation",
        BooleanSMTModel,
        name="boolean_smt",
        kind="constraint",
        components=(
            "Add",
            "BitVectorSBox",
            "BitwiseAnd",
            "Constant",
            "Identity",
            "ModularAdd",
            "Permutation",
            "Rotate",
            "Xor",
        ),
        domains=("Bit", "Word"),
        drivers=("z3",),
        scope="generic_graph",
    ),
    _entry(
        "representation",
        WordXorDifferentialSMTModel,
        name="word_differential_smt",
        kind="constraint",
        components=(
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "Identity",
            "ModularAdd",
            "ModularSubtract",
            "Permutation",
            "Rotate",
            "Shift",
            "Xor",
        ),
        domains=("Word",),
        drivers=("z3",),
        scope="generic_graph",
    ),
    _entry(
        "representation",
        WordXorLinearSMTModel,
        name="word_linear_smt",
        kind="constraint",
        components=(
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "Identity",
            "ModularAdd",
            "ModularSubtract",
            "Permutation",
            "Rotate",
            "Shift",
            "Xor",
        ),
        domains=("Word",),
        drivers=("z3",),
        scope="generic_graph",
    ),
)
