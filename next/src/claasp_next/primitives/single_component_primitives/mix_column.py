"""One-component finite-field matrix primitive."""

from claasp_next.components import LinearMap
from claasp_next.domains import BinaryExtensionField
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import (
    first_irreducible_polynomial, identity_matrix, matrix_is_invertible,
    normalize_matrix,
)
from ._base import positive


class MixColumn(Primitive):
    def __init__(self, word_size: int = 4, matrix=None, irreducible_polynomial: int = 0) -> None:
        word_size = positive(word_size, "word_size")
        matrix = normalize_matrix(identity_matrix(4) if matrix is None else matrix)
        modulus = irreducible_polynomial or first_irreducible_polynomial(word_size)
        field = BinaryExtensionField(word_size, modulus)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, field)
            else PrimitiveKind.FUNCTION
        )
        super().__init__(
            "mix_column", {"input": ValueType(field, (len(matrix[0]),))}, kind=kind,
        )
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), matrix)))


__all__ = ["MixColumn"]
