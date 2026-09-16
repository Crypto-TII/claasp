"""One-component primitive fixtures over the public typed component catalogue."""

from claasp_next.primitives.single_component_primitives._definitions import (
    And, Constant, Fsr, IdeaModmul, Identity, LinearLayer, MixColumn, Modadd,
    Modmul, Modsub, Not, Or, Permutation, Reverse, Rotate, Sbox, Shift,
    ShiftRows, Sigma, ThetaGaston, ThetaKeccak, ThetaXoodoo, VariableRotate,
    VariableShift, WordPermutation, Xor,
)
from claasp_next.primitives._catalogue_exports import CATEGORY_EXPORTS, load_export

__all__ = [
    "And", "Constant", "Fsr", "IdeaModmul", "Identity", "LinearLayer",
    "MixColumn", "Modadd", "Modmul", "Modsub", "Not", "Or", "Permutation",
    "Reverse", "Rotate", "Sbox", "Shift", "ShiftRows", "Sigma", "ThetaGaston",
    "ThetaKeccak", "ThetaXoodoo", "VariableRotate", "VariableShift",
    "WordPermutation", "Xor",
]

_PUBLIC = CATEGORY_EXPORTS["single_component_primitives"]
__all__ = sorted(set(__all__) | set(_PUBLIC))


def __getattr__(name: str):
    value = load_export(name, _PUBLIC)
    globals()[name] = value
    return value
