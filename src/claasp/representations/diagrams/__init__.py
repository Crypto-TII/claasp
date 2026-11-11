"""Backend-neutral primitive diagrams and independent serializers."""

from claasp._catalogue_metadata import _entry
from claasp.representations.diagrams.ascii import ASCIIArtSerializer
from claasp.representations.diagrams.compiler import DiagramCompiler
from claasp.representations.diagrams.model import (
    DiagramEdge,
    DiagramNode,
    DiagramRound,
    PrimitiveDiagram,
)
from claasp.representations.diagrams.tikz import TikZSerializer

__all__ = [
    "ASCIIArtSerializer",
    "DiagramCompiler",
    "DiagramEdge",
    "DiagramNode",
    "DiagramRound",
    "PrimitiveDiagram",
    "TikZSerializer",
]


__catalogue__ = (
    _entry(
        "driver", ASCIIArtSerializer, name="ascii_diagram", kind="renderer", availability="builtin"
    ),
    _entry("driver", TikZSerializer, name="tikz_diagram", kind="renderer", availability="builtin"),
    _entry(
        "representation",
        DiagramCompiler,
        name="primitive_diagram",
        kind="diagram",
        components=(
            "Add",
            "BinaryAffineMap",
            "BitVectorSBox",
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "FeedbackRegister",
            "IDEAMultiply",
            "Identity",
            "LinearMap",
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
        ),
        domains=("BinaryExtensionField", "Bit", "PrimeField", "Word"),
        drivers=("ascii_diagram", "latex", "tikz_diagram"),
        scope="generic_graph",
    ),
)
