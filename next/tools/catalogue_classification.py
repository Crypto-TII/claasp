"""Reviewed catalogue bijectivity classifications shared by metadata tools."""

from __future__ import annotations

_CATEGORY_BIJECTIONS = frozenset(
    {
        "block_ciphers",
        "permutations",
        "tweakable_block_ciphers",
    }
)

# These fixed catalogue interfaces need a more precise classification than
# their broad taxonomy supplies.  ``True`` means that the designated
# data/state input is bijective when every auxiliary input is retained.  It
# does not claim that the joint multi-input map is a bijection.
REVIEWED_RETAINED_INPUT_OBLIGATIONS = {
    "Add": True,
    "BinaryAffineMap": True,
    "BitVectorSBox": True,
    "BitwiseAnd": False,
    "BitwiseNot": True,
    "BitwiseOr": False,
    "ChaChaKeystreamBlock": True,
    "CipherFour": True,
    "Constant": False,
    "Fancy": False,
    "FeedbackRegister": True,
    "Heys": True,
    "IDEAMultiply": True,
    "Identity": True,
    "LinearMap": True,
    "ModularAdd": True,
    "ModularMultiply": False,
    "ModularSubtract": True,
    "Multiply": False,
    "Permutation": True,
    "Power": True,
    "Rotate": True,
    "SBox": True,
    "Shift": False,
    "ToyAES": True,
    "ToyFeistel": True,
    "ToySPN1": True,
    "ToySPN2": True,
    "VariableRotate": True,
    "VariableShift": False,
    "Xor": True,
}


def classify_bijectivity(official_name: str, category: str) -> tuple[bool, str]:
    """Return the fixed-interface obligation and its review basis."""

    if official_name in REVIEWED_RETAINED_INPUT_OBLIGATIONS:
        return (
            REVIEWED_RETAINED_INPUT_OBLIGATIONS[official_name],
            "reviewed retained-input bijectivity classification (M10.10h7)",
        )
    return (
        category in _CATEGORY_BIJECTIONS,
        "reviewed fixed-length interface classification (M10.9b)",
    )


__all__ = ["REVIEWED_RETAINED_INPUT_OBLIGATIONS", "classify_bijectivity"]
