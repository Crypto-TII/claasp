"""Primitive consisting of one binary affine map."""

from claasp_next.components import BinaryAffineMap as BinaryAffineMapComponent
from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from claasp_next.utils import (
    first_irreducible_polynomial,
    identity_matrix,
    matrix_is_invertible,
    normalize_matrix,
)

from ._base import positive


class BinaryAffineMap(Primitive):
    """Apply one GF(2) affine map to every field element.

    The default is the identity map on one four-bit field element. Setting
    the offset to ``0011`` XORs that constant into the result.

    >>> f"{BinaryAffineMap(offset=0b0011).evaluate(0b1010):04b}"
    '1001'

    A matrix, word size, and number of field elements can all be selected:

    >>> swap_bits = [[0, 1], [1, 0]]
    >>> affine = BinaryAffineMap(swap_bits, offset=0b01, word_size=2, unit_count=3)
    >>> # 00, 01, 10 become 01, 11, 00 respectively.
    >>> f"{affine.evaluate(0b00_01_10):06b}"
    '011100'


    EXAMPLES::

        >>> primitive = BinaryAffineMap()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self, matrix=None, offset: int = 0, word_size: int = 4, unit_count: int = 1
    ) -> None:
        word_size = positive(word_size, "word_size")
        unit_count = positive(unit_count, "unit_count")
        matrix = normalize_matrix(identity_matrix(word_size) if matrix is None else matrix)
        field = BinaryExtensionField(word_size, first_irreducible_polynomial(word_size))
        kind = (
            PrimitiveKind.PERMUTATION
            if matrix_is_invertible(matrix, Bit())
            else PrimitiveKind.FUNCTION
        )
        super().__init__("binary_affine_map", {"input": ValueType(field, (unit_count,))}, kind=kind)
        self.add_round()
        output = self.add_component(BinaryAffineMapComponent(self.input("input"), matrix, offset))
        self.set_output(output)


__all__ = ["BinaryAffineMap"]
