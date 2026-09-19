"""Primitive consisting of one domain-polymorphic linear map."""

from claasp_next.components import LinearMap as LinearMapComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import identity_matrix, matrix_is_invertible, normalize_matrix


class LinearMap(Primitive):
    """Apply a row-major matrix over a chosen scalar domain.

    The default domain is GF(2). With input vector ``[1, 0]``, the rows
    ``[1, 0]`` and ``[1, 1]`` both produce 1, giving output ``11``.

    >>> f"{LinearMap([[1, 0], [1, 1]]).evaluate(0b10):02b}"
    '11'

    Select a field domain to express a MixColumn-style matrix with the same
    component:

    >>> from claasp_next import BinaryExtensionField
    >>> field = BinaryExtensionField(4, 0b10011)
    >>> mixing = LinearMap([[1, 2], [2, 1]], domain=field)
    >>> hex(mixing.evaluate(0x12))
    '0x50'


    EXAMPLES::

        >>> primitive = LinearMap()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, matrix=None, domain=None) -> None:
        domain = Bit() if domain is None else domain
        matrix = normalize_matrix(identity_matrix(4) if matrix is None else matrix)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, domain)
            else PrimitiveKind.FUNCTION
        )
        super().__init__("linear_map", {"input": ValueType(domain, (len(matrix[0]),))}, kind=kind)
        self.add_round()
        output = self.add_component(LinearMapComponent(self.input("input"), matrix))
        self.set_output(output)


__all__ = ["LinearMap"]
