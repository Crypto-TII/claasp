"""One-component binary linear-layer primitive."""

from claasp_next.components import LinearMap
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import (
    identity_matrix, matrix_is_invertible, normalize_matrix, transpose_matrix,
)
from ._base import positive


class LinearLayer(Primitive):
    def __init__(self, bit_size: int = 4, description=None, *, matrix=None) -> None:
        bit_size = positive(bit_size, "bit_size")
        if description is not None and matrix is not None:
            raise ValueError("use either matrix or legacy description, not both")
        if matrix is None:
            # The v4 description stores output columns; v5 matrices are row-major.
            columns = identity_matrix(bit_size) if description is None else description
            matrix = transpose_matrix(columns)
        else:
            matrix = normalize_matrix(matrix)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, Bit())
            else PrimitiveKind.FUNCTION
        )
        super().__init__("linear_layer", {"input": ValueType(Bit(), (bit_size,))}, kind=kind)
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), matrix)))


__all__ = ["LinearLayer"]
