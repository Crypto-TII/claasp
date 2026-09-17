"""Primitive consisting of one whole-bit-vector S-box."""

from collections.abc import Sequence
from claasp_next.components import BitVectorSBox as BitVectorSBoxComponent
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveKind, ValueType
from ._base import positive


class BitVectorSBox(Primitive):
    """Use an entire bit vector as one lookup-table index.

    >>> BitVectorSBox(2, [3, 2, 1, 0]).evaluate(1)
    2
    """

    def __init__(
        self,
        input_bit_size: int = 4,
        lookup_table: Sequence[int] | None = None,
        output_bit_size: int | None = None,
    ) -> None:
        input_bit_size = positive(input_bit_size, "input_bit_size")
        table = (
            list(range(1 << input_bit_size))
            if lookup_table is None
            else list(lookup_table)
        )
        output_bit_size = (
            input_bit_size
            if output_bit_size is None
            else positive(output_bit_size, "output_bit_size")
        )
        bijective = output_bit_size == input_bit_size and sorted(table) == list(
            range(1 << input_bit_size)
        )
        kind = PrimitiveKind.PERMUTATION if bijective else PrimitiveKind.FUNCTION
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
