"""Meanings that may be propagated through a cipher graph."""

from claasp_next.interpretations.base import (
    CONCRETE, LEAKAGE, SYMBOLIC, XOR_DIFFERENTIAL, XOR_LINEAR, Interpretation,
)

__all__ = [
    "CONCRETE", "Interpretation", "LEAKAGE", "SYMBOLIC",
    "XOR_DIFFERENTIAL", "XOR_LINEAR",
]
