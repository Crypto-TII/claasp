"""Types carried by unit arrays in a CLAASP graph."""

from dataclasses import dataclass
from functools import reduce
from operator import mul

from claasp.unit_types.base import UnitType


@dataclass(frozen=True, slots=True)
class UnitArrayType:
    """Describe the unit type and shape of a homogeneous array.

    The logical size is deliberately distinct from its binary encoding size.

    EXAMPLES::

        >>> from claasp import UnitArrayType
        >>> from claasp.unit_types import PrimeField
        >>> state_type = UnitArrayType(unit_type=PrimeField(17), shape=(3,))
        >>> state_type.unit_count
        3
        >>> state_type.encoded_bit_size
        15
    """

    unit_type: UnitType
    shape: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.unit_type, UnitType):
            raise TypeError("unit_type must be a UnitType")
        if not self.shape:
            raise ValueError("shape must contain at least one dimension")
        if any(
            not isinstance(size, int) or isinstance(size, bool) or size <= 0 for size in self.shape
        ):
            raise ValueError("every shape dimension must be a positive integer")

    @property
    def unit_count(self) -> int:
        """Number of logical scalar units in the value."""

        return reduce(mul, self.shape, 1)

    @property
    def encoded_bit_size(self) -> int | None:
        """Canonical encoded size when the unit type defines one."""

        scalar_size = self.unit_type.encoded_bit_size
        return None if scalar_size is None else self.unit_count * scalar_size


def BitWord(bit_size: int) -> UnitArrayType:
    """Return the array type for one packed string of individual bits.

    ``BitWord(128)`` is the concise authoring form of
    ``UnitArrayType(unit_type=Bit(), shape=(128,))``. Use ``Word`` instead when
    the value is one arithmetic word with rotation or modular-add semantics.

    EXAMPLES::

        >>> from claasp import BitWord
        >>> array_type = BitWord(128)
        >>> (array_type.unit_count, array_type.encoded_bit_size)
        (128, 128)
    """

    from claasp.unit_types import Bit

    if not isinstance(bit_size, int) or isinstance(bit_size, bool):
        raise TypeError("bit_size must be an integer")
    if bit_size <= 0:
        raise ValueError("bit_size must be positive")
    return UnitArrayType(Bit(), (bit_size,))
