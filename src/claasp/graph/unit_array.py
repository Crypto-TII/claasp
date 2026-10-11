"""Identified typed arrays carried through a primitive graph."""

from dataclasses import dataclass

from claasp.graph.unit_array_type import UnitArrayType
from claasp.unit_types.base import UnitType


@dataclass(frozen=True, slots=True, init=False)
class UnitArray:
    """An identified array supplied or produced by a primitive graph.

    Positions refer to logical units rather than encoded bits.

    Pass an existing ``array_type`` or provide ``unit_type`` and ``shape``
    directly. These forms are equivalent.

    EXAMPLES::

        >>> from claasp import UnitArray, UnitArrayType
        >>> from claasp.unit_types import PrimeField
        >>> state = UnitArray("state", unit_type=PrimeField(17), shape=(3,))
        >>> state.select(2, 0).positions
        (2, 0)
        >>> state.select_all().array_type.unit_count
        3
    """

    source_id: str
    array_type: UnitArrayType

    def __init__(
        self,
        source_id: str,
        array_type: UnitArrayType | None = None,
        *,
        unit_type: UnitType | None = None,
        shape: tuple[int, ...] | None = None,
    ) -> None:
        """Create a graph array from a type object or its two constituents."""

        if not isinstance(source_id, str):
            raise TypeError("source_id must be a string")
        if not source_id:
            raise ValueError("source_id must not be empty")
        if array_type is not None:
            if unit_type is not None or shape is not None:
                raise TypeError("provide array_type or unit_type and shape, not both")
            if not isinstance(array_type, UnitArrayType):
                raise TypeError("array_type must be a UnitArrayType")
        else:
            if unit_type is None or shape is None:
                raise TypeError("provide array_type or both unit_type and shape")
            array_type = UnitArrayType(unit_type=unit_type, shape=shape)

        object.__setattr__(self, "source_id", source_id)
        object.__setattr__(self, "array_type", array_type)

    @property
    def unit_type(self) -> UnitType:
        """Return the type of each logical unit in the array."""

        return self.array_type.unit_type

    @property
    def shape(self) -> tuple[int, ...]:
        """Return the logical array shape."""

        return self.array_type.shape

    def select(self, *positions: int) -> "Selection":
        """Select logical unit positions from this array."""

        return Selection(self, positions)

    def select_all(self) -> "Selection":
        """Select every logical scalar position in order."""

        return Selection(self, tuple(range(self.array_type.unit_count)))

    def __getitem__(self, positions: int | slice | tuple[int, ...]) -> "Selection":
        """Select units with ordinary indexing syntax."""

        if isinstance(positions, tuple):
            return self.select(*positions)
        if isinstance(positions, slice):
            return self.select(*range(self.array_type.unit_count)[positions])
        return self.select(positions)


@dataclass(frozen=True, slots=True)
class Selection:
    """Represent an ordered selection of logical units from a source array.

    EXAMPLES::

        >>> from claasp import UnitArray, UnitArrayType
        >>> from claasp.unit_types import PrimeField
        >>> selection = Selection(UnitArray("state", UnitArrayType(PrimeField(17), (3,))), (2, 0))
        >>> (selection.positions, selection.array_type.shape)
        ((2, 0), (2,))
    """

    source: UnitArray
    positions: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source, UnitArray):
            raise TypeError("source must be a UnitArray")
        if not isinstance(self.positions, tuple):
            raise TypeError("positions must be a tuple")
        if not self.positions:
            raise ValueError("a selection must contain at least one position")

        size = self.source.array_type.unit_count
        for position in self.positions:
            if not isinstance(position, int) or isinstance(position, bool):
                raise TypeError("selection positions must be integers")
            if position < 0 or position >= size:
                raise ValueError(
                    f"position {position} is outside source {self.source.source_id!r} "
                    f"with {size} logical units"
                )

    @property
    def array_type(self) -> UnitArrayType:
        """Type produced by this flattened logical-unit selection."""

        return UnitArrayType(self.source.array_type.unit_type, (len(self.positions),))

    def __getitem__(self, positions: int | slice | tuple[int, ...]) -> "Selection":
        """Select positions relative to this selection."""

        requested = positions if isinstance(positions, tuple) else (positions,)
        if len(requested) == 1 and isinstance(requested[0], slice):
            selected = self.positions[requested[0]]
        else:
            selected = tuple(self.positions[position] for position in requested)
        return Selection(self.source, tuple(selected))


UnitArrayLike = UnitArray | Selection


def as_selection(value: UnitArrayLike) -> Selection:
    """Normalize a whole array or preserve an existing selection.

    EXAMPLES::

        >>> from claasp import UnitArray, UnitArrayType
        >>> from claasp.unit_types import Bit
        >>> as_selection(UnitArray("state", UnitArrayType(Bit(), (2,)))).positions
        (0, 1)
    """

    if isinstance(value, UnitArray):
        return value.select_all()
    if isinstance(value, Selection):
        return value
    raise TypeError("component input must be a UnitArray or Selection")
