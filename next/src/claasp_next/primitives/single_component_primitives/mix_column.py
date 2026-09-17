"""One-component finite-field matrix primitive."""

from claasp_next.components import LinearMap
from claasp_next.domains import BinaryExtensionField
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import field_matrix_is_invertible, first_irreducible, positive


class MixColumn(Primitive):
    def __init__(self, word_size: int = 4, matrix=None, irreducible_polynomial: int = 0) -> None:
        word_size = positive(word_size, "word_size")
        frozen = tuple(tuple(row) for row in (matrix or tuple(
            tuple(int(i == j) for j in range(4)) for i in range(4)
        )))
        modulus = irreducible_polynomial or first_irreducible(word_size)
        field = BinaryExtensionField(word_size, modulus)
        kind = (
            PrimitiveKind.PERMUTATION
            if field_matrix_is_invertible(frozen, field)
            else PrimitiveKind.FUNCTION
        )
        super().__init__("mix_column", {"input": ValueType(field, (len(frozen[0]),))}, kind=kind)
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), frozen)))


__all__ = ["MixColumn"]
