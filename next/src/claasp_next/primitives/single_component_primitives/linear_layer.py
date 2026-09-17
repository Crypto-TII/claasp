"""One-component binary linear-layer primitive."""

from claasp_next.components import LinearMap
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import (
    identity_matrix, matrix_is_invertible, normalize_matrix,
)


class LinearLayer(Primitive):
    """Apply a row-major binary matrix, inferring the input size from it."""

    def __init__(self, matrix=None) -> None:
        matrix = normalize_matrix(identity_matrix(4) if matrix is None else matrix)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, Bit())
            else PrimitiveKind.FUNCTION
        )
        super().__init__(
            "linear_layer", {"input": ValueType(Bit(), (len(matrix[0]),))}, kind=kind,
        )
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), matrix)))


__all__ = ["LinearLayer"]
