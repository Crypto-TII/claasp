"""Primitive consisting of one whole-bit-vector S-box."""

from collections.abc import Sequence

from claasp.components import (
    BitVectorSBox as BitVectorSBoxComponent,
)
from claasp.components import (
    LookupTable,
)
from claasp.domains import Bit
from claasp.graph import Primitive, PrimitiveKind, ValueType


class BitVectorSBox(Primitive):
    """Use an entire bit vector as one lookup-table index.

    In this two-bit example the table maps indices ``0, 1, 2, 3`` to
    ``3, 2, 1, 0`` respectively, so input ``01`` maps to ``10``.

    >>> reverse = BitVectorSBox(input_bit_size=2, lookup_table=[3, 2, 1, 0])
    >>> f"{reverse.evaluate(0b01):02b}"
    '10'

    The output width may differ from the input width:

    >>> compress = BitVectorSBox(2, [0, 0, 1, 1], output_bit_size=1)
    >>> compress.evaluate(0b10)
    1


    EXAMPLES::

        >>> primitive = BitVectorSBox()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self,
        input_bit_size: int = 4,
        lookup_table: Sequence[int] | None = None,
        output_bit_size: int | None = None,
    ) -> None:
        table = (
            LookupTable.identity(input_bit_size, output_bit_size)
            if lookup_table is None
            else LookupTable(lookup_table, input_bit_size, output_bit_size)
        )
        kind = PrimitiveKind.PERMUTATION if table.is_bijective() else PrimitiveKind.FUNCTION
        super().__init__(
            "bit_vector_sbox",
            {"input": ValueType(Bit(), (table.input_bit_size,))},
            kind=kind,
        )
        self._builder.add_round()
        output = self._builder.add_component(
            BitVectorSBoxComponent(self.graph.input("input"), table)
        )
        self._builder.set_output(output)


__all__ = ["BitVectorSBox"]
