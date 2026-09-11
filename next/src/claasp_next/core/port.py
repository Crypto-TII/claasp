"""Typed component and cipher ports."""

from dataclasses import dataclass

from claasp_next.core.value_type import ValueType


@dataclass(frozen=True, slots=True)
class Port:
    """A named source of a typed value in a cipher graph.

    Positions refer to logical units rather than encoded bits.

    EXAMPLES::

        >>> from claasp_next import Port, PrimeField, ValueType
        >>> state = Port("state", ValueType(PrimeField(17), (3,)))
        >>> state.select(2, 0).positions
        (2, 0)
        >>> state.select_all().value_type.unit_count
        3
    """

    owner_id: str
    value_type: ValueType

    def __post_init__(self) -> None:
        if not isinstance(self.owner_id, str):
            raise TypeError("owner_id must be a string")
        if not self.owner_id:
            raise ValueError("owner_id must not be empty")
        if not isinstance(self.value_type, ValueType):
            raise TypeError("value_type must be a ValueType")

    def select(self, *positions: int) -> "Selection":
        """Select logical scalar positions from this port."""

        return Selection(self, positions)

    def select_all(self) -> "Selection":
        """Select every logical scalar position in order."""

        return Selection(self, tuple(range(self.value_type.unit_count)))

    def __getitem__(self, positions: int | slice | tuple[int, ...]) -> "Selection":
        """Select units with ordinary indexing syntax."""

        if isinstance(positions, tuple):
            return self.select(*positions)
        if isinstance(positions, slice):
            return self.select(*range(self.value_type.unit_count)[positions])
        return self.select(positions)


@dataclass(frozen=True, slots=True)
class Selection:
    """An ordered selection of logical units from a source port."""

    source: Port
    positions: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, Port):
            raise TypeError("source must be a Port")
        if not isinstance(self.positions, tuple):
            raise TypeError("positions must be a tuple")
        if not self.positions:
            raise ValueError("a selection must contain at least one position")

        size = self.source.value_type.unit_count
        for position in self.positions:
            if not isinstance(position, int) or isinstance(position, bool):
                raise TypeError("selection positions must be integers")
            if position < 0 or position >= size:
                raise ValueError(
                    f"position {position} is outside source {self.source.owner_id!r} "
                    f"with {size} logical units"
                )

    @property
    def value_type(self) -> ValueType:
        """Type produced by this flattened logical-unit selection."""

        return ValueType(self.source.value_type.domain, (len(self.positions),))

    def __getitem__(self, positions: int | slice | tuple[int, ...]) -> "Selection":
        """Select positions relative to this selection."""

        requested = positions if isinstance(positions, tuple) else (positions,)
        if len(requested) == 1 and isinstance(requested[0], slice):
            selected = self.positions[requested[0]]
        else:
            selected = tuple(self.positions[position] for position in requested)
        return Selection(self.source, tuple(selected))


PortLike = Port | Selection


def as_selection(value: PortLike) -> Selection:
    """Normalize a whole port or an existing selection."""

    if isinstance(value, Port):
        return value.select_all()
    if isinstance(value, Selection):
        return value
    raise TypeError("component input must be a Port or Selection")
