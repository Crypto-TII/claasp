"""Reusable mathematical and layout helpers for primitive authors."""

from claasp.utils.finite_fields import (
    binary_field_multiply,
    binary_field_power,
    first_irreducible_polynomial,
)
from claasp.utils.integers import (
    bitmask,
    bits_little_endian,
    bytes_to_int,
    coerce_exact_int,
    int_to_bytes,
    int_to_words,
    rotate_left,
    rotate_right,
    words_to_int,
)
from claasp.utils.layouts import reverse_bytes_in_words
from claasp.utils.matrices import (
    identity_matrix,
    matrix_is_invertible,
    normalize_matrix,
    repeat_block_diagonal,
    transpose_matrix,
)
from claasp.utils.sequences import (
    rotate_left as rotate_sequence_left,
)
from claasp.utils.sequences import (
    rotate_right as rotate_sequence_right,
)
from claasp.utils.sequences import (
    shift_left,
    shift_right,
)

__all__ = [
    "binary_field_multiply",
    "binary_field_power",
    "bitmask",
    "bits_little_endian",
    "bytes_to_int",
    "coerce_exact_int",
    "first_irreducible_polynomial",
    "identity_matrix",
    "int_to_bytes",
    "int_to_words",
    "matrix_is_invertible",
    "normalize_matrix",
    "repeat_block_diagonal",
    "reverse_bytes_in_words",
    "rotate_left",
    "rotate_right",
    "rotate_sequence_left",
    "rotate_sequence_right",
    "shift_left",
    "shift_right",
    "transpose_matrix",
    "words_to_int",
]
