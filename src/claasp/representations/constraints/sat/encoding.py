"""Stable binary names and values for Boolean representation boundaries."""

from collections.abc import Mapping

from claasp.domains import Bit, Word
from claasp.graph import Selection, ValueType


def unit_variable_names(owner_id: str, value_type: ValueType, position: int) -> tuple[str, ...]:
    """Return the MSB-first Boolean variables encoding one logical unit."""

    domain = value_type.domain
    if isinstance(domain, Bit):
        return (f"{owner_id}_{position}",)
    if isinstance(domain, Word):
        return tuple(f"{owner_id}_{position}_{bit}" for bit in range(domain.width))
    raise ValueError(
        "Boolean encoding requires the Bit or Word domain; "
        f"{owner_id!r} uses {type(domain).__name__}"
    )


def selection_variable_names(selection: Selection) -> tuple[tuple[str, ...], ...]:
    """Return Boolean variable groups for a logical graph selection."""

    return tuple(
        unit_variable_names(selection.source.owner_id, selection.source.value_type, position)
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

    width = selection.value_type.domain.encoded_bit_size
    if width is None:
        raise ValueError("Boolean encoding requires a canonically encoded selection domain")
    names = []
    for owner_id, flat_bit in primitive.selection_bit_sources(selection):
        value_type = primitive.port(owner_id).value_type
        source_width = value_type.domain.encoded_bit_size
        if source_width is None:  # pragma: no cover - guarded by selection_bit_sources
            raise ValueError("Boolean encoding requires canonically encoded source domains")
        position, local_bit = divmod(flat_bit, source_width)
        names.append(unit_variable_names(owner_id, value_type, position)[local_bit])
    return tuple(tuple(names[start : start + width]) for start in range(0, len(names), width))


def encode_unit(value: int, value_type: ValueType) -> tuple[int, ...]:
    """Encode one logical Bit or Word value as MSB-first Boolean values."""

    domain = value_type.domain
    domain.validate(value)
    if isinstance(domain, Bit):
        return (value,)
    if isinstance(domain, Word):
        return tuple((value >> (domain.width - 1 - bit)) & 1 for bit in range(domain.width))
    raise ValueError(f"Boolean encoding does not support {type(domain).__name__}")


def decode_unit(names: tuple[str, ...], assignment: Mapping[str, int]) -> int:
    """Decode an MSB-first Boolean variable group from a named assignment."""

    return sum(assignment[name] << (len(names) - 1 - bit) for bit, name in enumerate(names))
