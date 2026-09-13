"""Compatibility imports for shared truncated-difference semantics."""

from claasp_next.semantics.cryptanalysis.truncated import (
    TruncatedBit,
    TruncatedXorDifference,
    propagate_two_word_speck_round,
    truncated_modular_add,
)

__all__ = [
    "TruncatedBit", "TruncatedXorDifference", "propagate_two_word_speck_round",
    "truncated_modular_add",
]
