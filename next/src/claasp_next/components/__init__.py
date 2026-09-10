"""Backend-independent operation descriptions."""

from claasp_next.components.algebraic import Add, LinearMap, Multiply, Power
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import ModularAdd, Rotate, Xor

__all__ = [
    "Add",
    "BitVectorSBox",
    "Concatenate",
    "Constant",
    "Identity",
    "LinearMap",
    "Multiply",
    "Permutation",
    "Power",
    "ModularAdd",
    "Rotate",
    "SBox",
    "Xor",
]
