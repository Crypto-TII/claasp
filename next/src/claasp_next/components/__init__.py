"""Backend-independent public component operation descriptions."""

from claasp_next.components.algebraic import (
    Add,
    BinaryAffineMap,
    LinearMap,
    Multiply,
    Power,
)
from claasp_next.components.feedback import (
    FeedbackRegister,
    FeedbackRegisterParameters,
    FeedbackRegisterSpec,
    FeedbackTerm,
)
from claasp_next.components.permutation import (
    gaston_theta,
    keccak_theta,
    shift_rows,
    sigma,
    xoodoo_theta,
)
from claasp_next.components.structural import (
    Constant,
    Identity,
    Permutation,
)
from claasp_next.components.substitution import BitVectorSBox, LookupTable, SBox
from claasp_next.components.word import (
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    IDEAMultiply,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)

__all__ = [
    "Add",
    "BinaryAffineMap",
    "BitVectorSBox",
    "BitwiseAnd",
    "BitwiseNot",
    "BitwiseOr",
    "Constant",
    "FeedbackRegister",
    "FeedbackRegisterParameters",
    "FeedbackRegisterSpec",
    "FeedbackTerm",
    "IDEAMultiply",
    "Identity",
    "LinearMap",
    "LookupTable",
    "ModularAdd",
    "ModularMultiply",
    "ModularSubtract",
    "Multiply",
    "Permutation",
    "Power",
    "Rotate",
    "SBox",
    "Shift",
    "VariableRotate",
    "VariableShift",
    "Xor",
    "gaston_theta",
    "keccak_theta",
    "shift_rows",
    "sigma",
    "xoodoo_theta",
]
