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
    "BitVectorSBox",
    "BitwiseAnd",
    "BitwiseNot",
    "BitwiseOr",
    "BinaryAffineMap",
    "Constant",
    "FeedbackRegister",
    "FeedbackRegisterParameters",
    "FeedbackRegisterSpec",
    "FeedbackTerm",
    "gaston_theta",
    "Identity",
    "IDEAMultiply",
    "LinearMap",
    "LookupTable",
    "keccak_theta",
    "Multiply",
    "Permutation",
    "Power",
    "ModularAdd",
    "ModularMultiply",
    "ModularSubtract",
    "Rotate",
    "Shift",
    "shift_rows",
    "sigma",
    "SBox",
    "VariableRotate",
    "VariableShift",
    "xoodoo_theta",
    "Xor",
]
