"""Primitive consisting of one whole-bit-vector S-box."""

from collections.abc import Sequence
from claasp_next.components import BitVectorSBox as BitVectorSBoxComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, ValueType
from ._base import (
    lookup_table_kind,
    lookup_table_or_identity,
    positive,
    positive_or_default,
)


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
    """

    def __init__(
        self,
        input_bit_size: int = 4,
        lookup_table: Sequence[int] | None = None,
        output_bit_size: int | None = None,
    ) -> None:
        input_bit_size = positive(input_bit_size, "input_bit_size")
        table = lookup_table_or_identity(lookup_table, input_bit_size)
        output_bit_size = positive_or_default(
            output_bit_size, input_bit_size, "output_bit_size"
        )
        kind = lookup_table_kind(table, input_bit_size, output_bit_size)
        super().__init__(
            "bit_vector_sbox", {"input": ValueType(Bit(), (input_bit_size,))}, kind=kind
        )
        self.add_round()
        output = self.add_component(
            BitVectorSBoxComponent(
                self.input("input"), table, output_bit_size=output_bit_size
            )
        )
        self.set_output(output)


__all__ = ["BitVectorSBox"]
