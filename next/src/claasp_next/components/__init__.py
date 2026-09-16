"""Backend-independent operation descriptions."""

from claasp_next.components.algebraic import Add, BinaryAffineMap, LinearMap, Multiply, Power
from claasp_next.components.conversion import PackBits, UnpackBits
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import (
    BitwiseAnd, BitwiseNot, BitwiseOr, IDEAMultiply, ModularAdd, ModularMultiply,
    ModularSubtract, Rotate, Shift, VariableRotate, VariableShift, Xor,
)

__all__ = [
    "Add",
    "BitVectorSBox",
    "BitwiseAnd",
    "BitwiseNot",
    "BitwiseOr",
    "BinaryAffineMap",
    "Concatenate",
    "Constant",
    "Identity",
    "IDEAMultiply",
    "LinearMap",
    "Multiply",
    "PackBits",
    "Permutation",
    "Power",
    "ModularAdd",
    "ModularMultiply",
    "ModularSubtract",
    "Rotate",
    "Shift",
    "SBox",
    "UnpackBits",
    "VariableRotate",
    "VariableShift",
    "Xor",
]
