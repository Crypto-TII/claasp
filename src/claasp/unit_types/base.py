"""Base definition for values stored in CLAASP unit arrays."""

from abc import ABC, abstractmethod


class UnitType(ABC):
    """Define the immutable semantics and validation of one logical unit.

    Concrete unit types implement membership and, when available, a canonical
    bit encoding width.

    EXAMPLES::

        >>> from claasp.unit_types import Bit
        >>> unit_type: UnitType = Bit()
        >>> unit_type.validate(1)
        >>> try:
        ...     unit_type.validate(2)
        ... except ValueError as error:
        ...     "not a canonical element" in str(error)
        True
    """

    @property
    @abstractmethod
    def encoded_bit_size(self) -> int | None:
        """Return the canonical unit encoding size, if one is defined."""

    @abstractmethod
    def contains(self, value: object) -> bool:
        """Return whether *value* is a canonical runtime representative."""

    def validate(self, value: object) -> None:
        """Raise ``ValueError`` when *value* is invalid for this unit type."""

        if not self.contains(value):
            raise ValueError(f"{value!r} is not a canonical element of {self!r}")
