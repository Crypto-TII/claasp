"""Backend-independent operation descriptions."""

from claasp_next.components.algebraic import Add, BinaryAffineMap, LinearMap, Multiply, Power
from claasp_next.components.conversion import PackBits, UnpackBits
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import BitwiseAnd, ModularAdd, Rotate, Xor

__all__ = [
    "Add",
    "BitVectorSBox",
    "BitwiseAnd",
    "BinaryAffineMap",
    "Concatenate",
    "Constant",
    "Identity",
    "LinearMap",
    "Multiply",
    "PackBits",
    "Permutation",
    "Power",
    "ModularAdd",
    "Rotate",
    "SBox",
    "UnpackBits",
    "Xor",
]
