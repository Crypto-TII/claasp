"""Stable binary names and values for Boolean representation boundaries."""

from collections.abc import Mapping

from claasp.graph import Selection, UnitArrayType
from claasp.unit_types import Bit, Word


def unit_variable_names(
    source_id: str, array_type: UnitArrayType, position: int
) -> tuple[str, ...]:
    """Return the MSB-first Boolean variables encoding one logical unit."""

    unit_type = array_type.unit_type
    if isinstance(unit_type, Bit):
        return (f"{source_id}_{position}",)
    if isinstance(unit_type, Word):
        return tuple(f"{source_id}_{position}_{bit}" for bit in range(unit_type.width))
    raise ValueError(
        "Boolean encoding requires the Bit or Word unit_type; "
        f"{source_id!r} uses {type(unit_type).__name__}"
    )


def selection_variable_names(selection: Selection) -> tuple[tuple[str, ...], ...]:
    """Return Boolean variable groups for a logical graph selection."""

    return tuple(
        unit_variable_names(selection.source.source_id, selection.source.array_type, position)
        for position in selection.positions
    )


def resolved_selection_variable_names(
    primitive,
    selection: Selection,
) -> tuple[tuple[str, ...], ...]:
    """Return Boolean variable groups after resolving structural bindings.

    Bindings have no variables of their own.  Their selected bits therefore
    inherit the stable names of the primitive inputs or semantic component
    outputs that carry them.
    """

    width = selection.array_type.unit_type.encoded_bit_size
    if width is None:
        raise ValueError("Boolean encoding requires a canonically encoded selection unit_type")
    names = []
    for source_id, flat_bit in primitive.graph.selection_bit_sources(selection):
        array_type = primitive.graph.unit_array(source_id).array_type
        source_width = array_type.unit_type.encoded_bit_size
        if source_width is None:  # pragma: no cover - guarded by selection_bit_sources
            raise ValueError("Boolean encoding requires canonically encoded source domains")
        position, local_bit = divmod(flat_bit, source_width)
        names.append(unit_variable_names(source_id, array_type, position)[local_bit])
    return tuple(tuple(names[start : start + width]) for start in range(0, len(names), width))


def encode_unit(value: int, array_type: UnitArrayType) -> tuple[int, ...]:
    """Encode one logical Bit or Word value as MSB-first Boolean values."""

    unit_type = array_type.unit_type
    unit_type.validate(value)
    if isinstance(unit_type, Bit):
        return (value,)
    if isinstance(unit_type, Word):
        return tuple((value >> (unit_type.width - 1 - bit)) & 1 for bit in range(unit_type.width))
    raise ValueError(f"Boolean encoding does not support {type(unit_type).__name__}")


def decode_unit(names: tuple[str, ...], assignment: Mapping[str, int]) -> int:
    """Decode an MSB-first Boolean variable group from a named assignment."""

    return sum(assignment[name] << (len(names) - 1 - bit) for bit, name in enumerate(names))
