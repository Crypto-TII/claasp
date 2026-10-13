"""Primitive consisting of one unit_type-polymorphic linear map."""

from claasp.components import LinearMap as LinearMapComponent
from claasp.graph import Primitive, PrimitiveKind, UnitArrayType
from claasp.unit_types import Bit
from claasp.utils import identity_matrix, matrix_is_invertible, normalize_matrix


class LinearMap(Primitive):
    """Apply a row-major matrix over a chosen scalar unit_type.

    The default unit_type is GF(2). With input vector ``[1, 0]``, the rows
    ``[1, 0]`` and ``[1, 1]`` both produce 1, giving output ``11``.

    >>> f"{LinearMap([[1, 0], [1, 1]]).evaluate(0b10):02b}"
    '11'

    Select a field unit_type to express a MixColumn-style matrix with the same
    component:

    >>> from claasp.unit_types import BinaryExtensionField
    >>> field = BinaryExtensionField(4, 0b10011)
    >>> mixing = LinearMap([[1, 2], [2, 1]], unit_type=field)
    >>> hex(mixing.evaluate(0x12))
    '0x50'


    EXAMPLES::

        >>> primitive = LinearMap()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(self, matrix=None, unit_type=None) -> None:
        unit_type = Bit() if unit_type is None else unit_type
        matrix = normalize_matrix(identity_matrix(4) if matrix is None else matrix)
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, unit_type)
            else PrimitiveKind.FUNCTION
        )
        super().__init__(
            "linear_map", {"input": UnitArrayType(unit_type, (len(matrix[0]),))}, kind=kind
        )
        self._builder.add_round()
        output = self._builder.add_component(LinearMapComponent(self.graph.input("input"), matrix))
        self._builder.set_output(output)


__all__ = ["LinearMap"]
