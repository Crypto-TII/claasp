"""One-component binary linear-layer primitive."""

from claasp_next.components import LinearMap
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import binary_matrix_is_invertible, positive


class LinearLayer(Primitive):
    def __init__(self, bit_size: int = 4, description=None) -> None:
        bit_size = positive(bit_size, "bit_size")
        matrix = tuple(tuple(row) for row in description) if description is not None else tuple(
            tuple(int(row == column) for column in range(bit_size)) for row in range(bit_size)
        )
        # Legacy descriptions store output columns; LinearMap stores rows.
        matrix = tuple(zip(*matrix))
        kind = (
            PrimitiveKind.PERMUTATION
            if binary_matrix_is_invertible(matrix)
            else PrimitiveKind.FUNCTION
        )
        super().__init__("linear_layer", {"input": ValueType(Bit(), (bit_size,))}, kind=kind)
        self.add_round()
        self.set_output(self.add_component(LinearMap(self.input("input"), matrix)))


__all__ = ["LinearLayer"]
