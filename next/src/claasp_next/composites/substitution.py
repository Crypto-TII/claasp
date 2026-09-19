"""Reusable substitution-layer composites."""

from collections.abc import Iterable

from claasp_next.components import BitVectorSBox, SBox
from claasp_next.domains import Bit
from claasp_next.domains.base import Domain
from claasp_next.graph import CompositeBuilder, CompositeDefinition, ValueType


def ParallelSBoxLayer(
    table: Iterable[int],
    box_count: int,
    *,
    domain: Domain | None = None,
) -> CompositeDefinition:
    """Return independent equal-width S-boxes applied in parallel.

    With no ``domain`` the boundary is one flat MSB-first bit vector and each
    box is a :class:`~claasp_next.components.BitVectorSBox`, which is directly consumable by Boolean
    constraint representations.  Supplying a finite encoded domain gives one
    logical unit per box and uses ordinary :class:`~claasp_next.components.SBox` leaves.

    EXAMPLES::

        >>> from claasp_next.composites import ParallelSBoxLayer
        >>> hex(ParallelSBoxLayer((0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD,
        ...     3, 0xE, 0xF, 8, 4, 7, 1, 2), 2).evaluate(0x0F))
        '0xc2'
    """

    frozen_table = tuple(table)
    if not isinstance(box_count, int) or isinstance(box_count, bool) or box_count <= 0:
        raise ValueError("box_count must be a positive integer")
    if not frozen_table or len(frozen_table) & (len(frozen_table) - 1):
        raise ValueError("S-box table length must be a positive power of two")
    width = len(frozen_table).bit_length() - 1
    if domain is None:
        input_type = ValueType(Bit(), (box_count * width,))
    else:
        if not isinstance(domain, Domain):
            raise TypeError("domain must be a Domain or None")
        if domain.encoded_bit_size != width:
            raise ValueError("domain encoding width must match the S-box table")
        input_type = ValueType(domain, (box_count,))

    builder = CompositeBuilder("ParallelSBoxLayer", {"state": input_type})
    builder.add_round()
    outputs = []
    for index in range(box_count):
        if domain is None:
            selection = builder.input("state")[index * width : (index + 1) * width]
            component = BitVectorSBox(selection, frozen_table, component_id=f"sbox_{index}")
        else:
            component = SBox(builder.input("state")[index], frozen_table, component_id=f"sbox_{index}")
        outputs.append(builder.add_component(component))
    output = builder.join(*outputs)
    builder.set_output("output", output)
    return builder.build(provenance={"construction": "independent parallel lookup tables"})
