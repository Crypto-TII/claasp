"""Primitive consisting of one domain-polymorphic linear map."""

from claasp_next.components import LinearMap as LinearMapComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import identity_matrix, matrix_is_invertible, normalize_matrix


class LinearMap(Primitive):
    """Apply a row-major matrix over a chosen scalar domain.

    >>> LinearMap([[1, 0], [1, 1]]).evaluate(0b10)
    3
    """

    def __init__(self, matrix=None, domain=None) -> None:
        domain = Bit() if domain is None else domain
        matrix = normalize_matrix(identity_matrix(4) if matrix is None else matrix)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, domain)
            else PrimitiveKind.FUNCTION
        )
        super().__init__(
            "linear_map", {"input": ValueType(domain, (len(matrix[0]),))}, kind=kind
        )
        self.add_round()
        output = self.add_component(LinearMapComponent(self.input("input"), matrix))
        self.set_output(output)


__all__ = ["LinearMap"]
