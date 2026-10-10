"""Base definitions for mathematical scalar domains."""

from abc import ABC, abstractmethod


class Domain(ABC):
    """Define the immutable semantics and validation of one scalar value.

    Concrete domains implement membership and, when available, a canonical
    bit encoding width.

    EXAMPLES::

        >>> from claasp.domains import Bit
        >>> domain: Domain = Bit()
        >>> domain.validate(1)
        >>> try:
        ...     domain.validate(2)
        ... except ValueError as error:
        ...     "not a canonical element" in str(error)
        True
    """

    @property
    @abstractmethod
    def encoded_bit_size(self) -> int | None:
        """Return the canonical scalar encoding size, if one is defined."""

    @abstractmethod
    def contains(self, value: object) -> bool:
        """Return whether *value* is a canonical runtime representative."""

    def validate(self, value: object) -> None:
        """Raise ``ValueError`` when *value* is outside this domain."""

        if not self.contains(value):
            raise ValueError(f"{value!r} is not a canonical element of {self!r}")
