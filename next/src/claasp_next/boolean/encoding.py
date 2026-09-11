"""Stable binary names and values for Boolean backend boundaries."""

from collections.abc import Mapping

from claasp_next.core import Selection, ValueType
from claasp_next.domains import Bit, Word


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
